package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

const (
	// sessionLife bounds a whole conversation; a client that stalls holds a slot no longer.
	sessionLife = 30 * time.Second
	// maxLine bounds a command line, the password in it included.
	maxLine = 512
	// refusalDelay is poppassd-ceti's pause before saying a password is wrong.
	refusalDelay = 3 * time.Second
)

// A Backend keeps the passwords.
type Backend interface {
	// Verify reports whether password is user's; an unknown user is not an error.
	Verify(user, password string) (bool, error)
	// Change sets user's password to next if current is still the password.
	Change(user, current, next string) error
}

// ErrRefused is a change the backend did not make because the current password is wrong.
var ErrRefused = errors.New("the current password is wrong")

// Server answers poppassd: USER, PASS, NEWPASS and QUIT, each with 200 or with 500 and a
// reason, after which the connection closes.
type Server struct {
	Backend   Backend
	Limit     *Limiter
	MinLength int
	Log       *log.Logger
	// delay is refusalDelay; tests shorten it.
	delay time.Duration
}

func (s *Server) Serve(ln net.Listener, slots int) error {
	free := make(chan struct{}, slots)
	for {
		free <- struct{}{}
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { <-free }()
			s.serve(conn)
		}()
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(sessionLife))
	r := bufio.NewReaderSize(conn, maxLine)
	say := func(format string, args ...any) { fmt.Fprintf(conn, format+"\r\n", args...) }
	// read returns the argument of the expected command, or false after saying why not.
	read := func(command string) (string, bool) {
		line, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				say("500 Line too long")
			}
			return "", false
		}
		keyword, arg, _ := strings.Cut(strings.TrimRight(string(line), "\r\n"), " ")
		if !strings.EqualFold(keyword, command) {
			say("500 %s expected", command)
			return "", false
		}
		if strings.ContainsRune(arg, 0) {
			say("500 Invalid argument")
			return "", false
		}
		return arg, true
	}

	say("200 poppassd")
	user, ok := read("user")
	if !ok {
		return
	}
	if user == "" {
		say("500 Username required")
		return
	}
	say("200 Your password please")
	current, ok := read("pass")
	if !ok {
		return
	}
	if !s.Limit.Allow(user, time.Now()) {
		s.Log.Printf("%s: paused after failed attempts", user)
		say("500 Too many failed attempts, try again later")
		return
	}
	right, err := s.Backend.Verify(user, current)
	if err != nil {
		s.Log.Printf("%s: %v", user, err)
		say("500 Server error")
		return
	}
	if !right {
		s.refuse(conn, user)
		return
	}
	say("200 Your new password please")
	next, ok := read("newpass")
	if !ok {
		return
	}
	if len([]rune(next)) < s.MinLength {
		say("500 The new password is shorter than %d characters", s.MinLength)
		return
	}
	switch err := s.Backend.Change(user, current, next); {
	case errors.Is(err, ErrRefused):
		s.refuse(conn, user)
		return
	case err != nil:
		s.Log.Printf("%s: %v", user, err)
		say("500 Server error, password not changed")
		return
	}
	s.Log.Printf("%s: password changed", user)
	say("200 Password changed")
	if _, ok := read("quit"); ok {
		say("200 Bye")
	}
}

// refuse counts a wrong password or an unknown user alike, so neither tells which.
func (s *Server) refuse(conn net.Conn, user string) {
	s.Limit.Fail(user, time.Now())
	s.Log.Printf("%s: current password refused", user)
	time.Sleep(s.delay)
	fmt.Fprint(conn, "500 Old password is incorrect\r\n")
}

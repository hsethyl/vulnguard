package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)

func run(input string) {
	exec.Command("sh", "-c", input).Run()
}

func query(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%s", id))
}

func hash(data []byte) {
	_ = md5.New()
}

func client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

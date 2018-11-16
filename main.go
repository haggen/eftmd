package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/haggen/eftmd/pwatcher"
)

func main() {
	w := pwatcher.New()
	go w.Watch("Calculator.exe")
	defer w.Stop()

	w.Handle(func(pid int32) {
		if pid == 0 {
			log.Print("Game process was closed")
		} else {
			log.Printf("Game process found #%d", pid)
		}
	})

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	<-interrupt
	log.Print("Bye bye!")
}

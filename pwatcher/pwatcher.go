package pwatcher

import (
	"time"

	"github.com/shirou/gopsutil/process"
)

// Watcher watches for processes.
type Watcher struct {
	pid     int32
	handler func(int32)
	stopped chan bool
}

// Stop halts the watcher.
func (w *Watcher) Stop() {
	close(w.stopped)
}

// Watch polls running processes for one with given name and return the process ID when it starts, or 0 when it stops.
func (w *Watcher) Watch(target string) {
	ticker := time.Tick(time.Second)
	for {
		select {
		case <-w.stopped:
			return
		case <-ticker:
			if w.pid == 0 {
				procs, err := process.Processes()
				if err != nil {
					panic(err)
				}
				for _, proc := range procs {
					exe, err := proc.Name()
					if err != nil {
						continue
					}
					if target == exe {
						w.pid = proc.Pid
						w.handler(w.pid)
						break
					}
				}
			} else {
				ok, err := process.PidExists(int32(w.pid))
				if err != nil {
					panic(err)
				}
				if !ok {
					w.pid = 0
					w.handler(w.pid)
				}
			}
		}
	}
}

// Handle sets watcher handler for when process is found or killed.
func (w *Watcher) Handle(h func(int32)) {
	w.handler = h
}

// New initializes a new Watcher.
func New() *Watcher {
	return &Watcher{
		pid:     0,
		handler: func(p int32) {},
		stopped: make(chan bool, 1),
	}
}

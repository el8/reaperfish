package reaper

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"do/doge/log"
)

var logger = log.KV("module", "reaper")

// Instance is a run-time info about this instance of a daemon
type Instance struct {
	pollingPeriod time.Duration
}

func New() (*Instance, error) {
	var pollingPeriod time.Duration

	err := Startup()
	if err != nil {
		logger.Err(err).Error("Error creating Reaper instance")
		return nil, err
	}

	/*
	pollingPeriod, policy, cacheSize, err := readConfFile()
	if err != nil {
		logger.Err(err).Error("Error loading conf file")
		return nil, err
	}
	*/
	pollingPeriod = time.Millisecond

	rpr := Instance {
		pollingPeriod: pollingPeriod,
	}
	return &rpr, nil
}

func (i *Instance) tick() error {
	logger.Debug("Tick!")

	return nil
}

func (i *Instance) handleSignal(sig os.Signal) error {
	logger.KV("signal", sig).Info("signal received")

	switch sig {
	case syscall.SIGHUP:
		/*
		pollingPeriod, policy, cacheSize, err := readConfFile()
		if err != nil {
			logger.Err(err).KVs(log.F{"policy": policy, "pollingPeriod": pollingPeriod, "cacheSize": cacheSize}).Error("reconf error")
			return err
		}

		logger.KVs(log.F{"policy": policy, "pollingPeriod": pollingPeriod}).Info("reconf")
		i.pollingPeriod = pollingPeriod
		i.nextPolicy = policy
		*/
	default:
		logger.KV("signal", sig).Error("Unknown signal")
		return fmt.Errorf("Unknown signal %v", sig)
	}

	return nil
}

func (i *Instance) mainLoop() error {
	ranOnce := false

	// Create a channel to catch SIGHUPs
	sigc := make(chan os.Signal)
	signal.Notify(sigc, syscall.SIGHUP)

	for !(ranOnce) {
		select {
		case m := <-sigc:
			i.handleSignal(m)
		case <-time.After(i.pollingPeriod):
			i.tick()
			ranOnce = true
		}
	}
	return nil
}

func (i *Instance) Start() error {
	return i.mainLoop()
}

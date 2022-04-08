package main

import (
	"reaper"
)

var logger = log.KV("module", "reaper_main")

func main() {
	logger.Info("Reaper started")

	rpr, err := reaper.New()
	if err != nil {
		logger.Err(err).Fatal("Couldn't initialize the app")
	}

	err = rpr.Start()
	if err != nil {
		logger.Err(err).Fatal("Couldn't start the app")
	}

	logger.Info("Reaper exited")
}

package main

import (
	"log"
	"os"
)

type environment struct {
	deploymentsNamespace string
	developmentMode      bool
	webhookHostListen    string
	webhookHostAdvertise string
}

func readEnvironment() environment {
	developmentMode := os.Getenv("KUBEWARDEN_DEVELOPMENT_MODE")

	res := environment{
		deploymentsNamespace: os.Getenv("NAMESPACE"),
		developmentMode:      (developmentMode == "1" || developmentMode == "true"),
		webhookHostListen:    os.Getenv("WEBHOOK_HOST_LISTEN"),
		webhookHostAdvertise: os.Getenv("WEBHOOK_HOST_ADVERTISE"),
	}

	if res.developmentMode {
		switch {
		case res.webhookHostListen == "" && res.webhookHostAdvertise == "":
			log.Fatal("Either WEBHOOK_HOST_LISTEN or WEBHOOK_HOST_ADVERTISE has to be provided along with KUBEWARDEN_DEVELOPMENT_MODE")
		case res.webhookHostListen == "" && res.webhookHostAdvertise != "":
			res.webhookHostListen = res.webhookHostAdvertise
		case res.webhookHostListen != "" && res.webhookHostAdvertise == "":
			res.webhookHostAdvertise = res.webhookHostListen
		}
	}

	return res
}

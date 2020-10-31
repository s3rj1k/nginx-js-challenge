package main

import (
	"net/http"
	"sync"
	"time"
)

func cleanDB(db *sync.Map) {
	for {
		// sleep inside infinite loop
		time.Sleep(15 * time.Second)

		// range over db
		db.Range(func(key interface{}, val interface{}) bool {
			// cast key to string
			if id, ok := key.(string); ok {
				// cast value to challenge record
				if record, ok := val.(challengeDBRecord); ok {
					// check expiration time
					if record.Expires.Before(time.Now()) {
						Debug.Printf(
							"%d, Domain:'%s', ID:'%s', %s\n",
							http.StatusOK, record.Domain,
							id, messageExpiredRecord,
						)

						// check then id is NOT UUID
						if !reUUID.MatchString(id) {
							Bot.Printf(
								"%d, Domain:'%s', Addr:'%s', UA:'%s'\n",
								http.StatusTeapot, record.Domain,
								record.Address, record.UserAgent,
							)
						}

						// delete key
						db.Delete(key)
					}
				}
			}

			return true
		})
	}
}

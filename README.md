# certmon
A go application to monitor certificate updates for domains. Uses certstream for data and pushover for push notifications

To use, you need to upate the following code with proper pushover details:

	// Create a new pushover instance with a token
	push := pushover.New("YourAppTokenHere")

	// Create a new recipient
	recipient := pushover.NewRecipient("RecipientHere")
  
alerts.txt :    Contains keywords for which we want push notifications.

monitor.txt:    Keywords (typically a domain or top level domain) which we want to monitor to the console and log.

  highlight.txt:  Keywords which we want highlighted on the console. Only processes maches passed through the monitor filter.


# certmon
A go application to monitor domains. Uses certstream for data and pushover for push notifications

To use, you need to upate the following code with proper pushover details:

	// Create a new pushover instance with a token
	push := pushover.New("YourAppTokenHere")

	// Create a new recipient
	recipient := pushover.NewRecipient("RecipientHere")
  
alerts.txt :    Contains keywords for with we want push notifications.
monitor.txt:    Keywords (typically a domain or top level domain) which you want to monitor to the console and log.
  highlight.txt:  Keywords which you want highlighted on the console. Only processes maches passed though the monitor filter.


package main

import (
	"errors"
	"net"
)

// isTransportTimeout reports whether err ultimately came from a network
// deadline/timeout. A timeout is not evidence that the chunk size was too
// large: the physical connection may be dead and replaying the same logical
// request can also duplicate an upload whose response was lost. Treat it as a
// hard tunnel boundary instead of feeding it into the adaptive size controller.
func isTransportTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

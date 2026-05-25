// Copyright (C) 2016  The GoHBase Authors.  All rights reserved.
// This file is part of GoHBase.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the COPYING file.

package mock_test

import (
	"net"

	"github.com/acceldata-io/gohbase"
	"github.com/acceldata-io/gohbase/hrpc"
	"github.com/acceldata-io/gohbase/test/mock"
	regionMock "github.com/acceldata-io/gohbase/test/mock/region"
	zkMock "github.com/acceldata-io/gohbase/test/mock/zk"
	"github.com/acceldata-io/gohbase/zk"
)

var _ gohbase.Client = (*mock.MockClient)(nil)
var _ gohbase.RPCClient = (*mock.MockRPCClient)(nil)
var _ gohbase.AdminClient = (*mock.MockAdminClient)(nil)
var _ hrpc.Call = (*mock.MockCall)(nil)
var _ net.Conn = (*mock.MockConn)(nil)
var _ zk.Client = (*zkMock.MockClient)(nil)
var _ hrpc.RegionClient = (*regionMock.MockRegionClient)(nil)

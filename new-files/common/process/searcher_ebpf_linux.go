package process

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
)

// FindProcessInfoByPID resolves process metadata without scanning socket file
// descriptors across procfs. The caller already established socket ownership.
// Ported from the CHIZI-0618 fork for the eBPF inbound.
func FindProcessInfoByPID(processID uint32, userID uint32, packageManager tun.PackageManager) (*adapter.ConnectionOwner, error) {
	processInfo := &adapter.ConnectionOwner{
		ProcessID: processID,
		UserId:    int32(userID),
	}
	processPath, err := os.Readlink(filepath.Join(pathProc, strconv.FormatUint(uint64(processID), 10), "exe"))
	if err == nil {
		processInfo.ProcessPath = processPath
	}
	completeProcessInfo(processInfo, packageManager)
	return processInfo, err
}

func completeProcessInfo(info *adapter.ConnectionOwner, packageManager tun.PackageManager) {
	if info.UserId != -1 && info.UserName == "" {
		osUser, _ := user.LookupId(F.ToString(info.UserId))
		if osUser != nil {
			info.UserName = osUser.Username
		}
	}
	if packageManager == nil || info.UserId == -1 {
		return
	}
	appID := uint32(info.UserId) % 100000
	var packageNames []string
	if sharedPackage, loaded := packageManager.SharedPackageByID(appID); loaded {
		packageNames = append(packageNames, sharedPackage)
	}
	if packages, loaded := packageManager.PackagesByID(appID); loaded {
		packageNames = append(packageNames, packages...)
	}
	info.AndroidPackageNames = common.Uniq(packageNames)
}

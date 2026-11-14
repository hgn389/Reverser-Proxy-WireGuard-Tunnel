package webpanel

import (
	"regexp"
	"strings"
)

var panelMessagesVI = map[string]string{
	"Operation completed successfully.":                                              "Thao tác hoàn tất thành công.",
	"No certificate status was returned.":                                            "Không nhận được trạng thái chứng chỉ.",
	"The managed certificate file was not found.":                                    "Không tìm thấy tệp chứng chỉ được quản lý.",
	"WireGuard peer management is unavailable":                                       "Chức năng quản lý peer WireGuard hiện không khả dụng",
	"the privileged helper returned invalid peer data":                               "Dịch vụ đặc quyền trả về dữ liệu peer không hợp lệ",
	"Confirm that you will update the device configuration or scan its new QR code.": "Xác nhận rằng bạn sẽ cập nhật cấu hình thiết bị hoặc quét mã QR mới.",
	"system update is unavailable":                                                   "Chức năng cập nhật hệ thống hiện không khả dụng",
	"manage the web panel proxy with rpctl web commands":                             "Quản lý proxy của bảng điều khiển bằng các lệnh rpctl web",
	"mode is allowed only when changing a WireGuard peer mode":                       "Chỉ được chỉ định chế độ khi thay đổi chế độ peer WireGuard",
	"VPN IP Local is allowed only when adding a WireGuard peer":                      "Chỉ được chỉ định VPN IP Local khi thêm peer WireGuard",
	"peer is not allowed for this operation":                                         "Thao tác này không cho phép chỉ định peer",
	"upstream is not allowed for this operation":                                     "Thao tác này không cho phép chỉ định upstream",
	"wg_peer_add accepts only a peer name and VPN IP Local":                          "wg_peer_add chỉ chấp nhận tên peer và VPN IP Local",
	"wg_peer_mode accepts only a peer name and mode":                                 "wg_peer_mode chỉ chấp nhận tên peer và chế độ",
	"VPN IP Local must be a whole number from 1 to 254":                              "VPN IP Local phải là số nguyên từ 1 đến 254",
	"operation is not allowed":                                                       "Thao tác không được phép",
	"privileged operation failed":                                                    "Thao tác đặc quyền thất bại",
	"request is too large":                                                           "Yêu cầu quá lớn",
	"request must contain exactly one JSON object":                                   "Yêu cầu phải chứa đúng một đối tượng JSON",
	"update needs root privileges":                                                   "Cập nhật cần quyền root",
	"another rpctl update is already running":                                        "Một tiến trình cập nhật rpctl khác đang chạy",
	"release checksum mismatch; update was not installed":                            "Mã kiểm tra bản phát hành không khớp; bản cập nhật chưa được cài đặt",
	"release file exceeds the allowed size":                                          "Tệp bản phát hành vượt quá kích thước cho phép",
	"update repository must use owner/name format":                                   "Kho cập nhật phải có định dạng owner/name",
	"refusing to replace a non-regular rpctl installation":                           "Từ chối thay thế bản cài đặt rpctl không phải tệp thông thường",
	"binary returned an invalid version string":                                      "Tệp thực thi trả về chuỗi phiên bản không hợp lệ",
	"GitHub latest release redirect was malformed":                                   "Chuyển hướng đến bản phát hành mới nhất trên GitHub không hợp lệ",
	"too many redirects":                                                             "Quá nhiều lần chuyển hướng",
	"release download redirected outside GitHub HTTPS hosts":                         "Tải bản phát hành bị chuyển hướng ra ngoài các máy chủ HTTPS của GitHub",
	"web panel configuration is not a regular file":                                  "Cấu hình bảng điều khiển không phải tệp thông thường",
	"Tailscale is not installed":                                                     "Tailscale chưa được cài đặt",
	"Tailscale status response is too large":                                         "Phản hồi trạng thái Tailscale quá lớn",
	"Tailscale returned invalid status data":                                         "Tailscale trả về dữ liệu trạng thái không hợp lệ",
	"peer name must contain 1-32 letters, numbers, underscores, or hyphens and start with a letter or number": "Tên peer phải gồm 1-32 chữ cái, chữ số, dấu gạch dưới hoặc gạch nối và bắt đầu bằng chữ cái hoặc chữ số",
	"site already exists":                              "Trang web đã tồn tại",
	"domain must be a lowercase DNS name":              "Tên miền phải là tên DNS viết thường",
	"site domain must be a DNS name":                   "Tên miền trang web phải là tên DNS",
	"invalid upstream URL":                             "URL upstream không hợp lệ",
	"upstream scheme must be http or https":            "Giao thức upstream phải là http hoặc https",
	"upstream must contain only scheme, host and port": "Upstream chỉ được chứa giao thức, máy chủ và cổng",
	"invalid upstream host":                            "Máy chủ upstream không hợp lệ",
	"upstream port is required":                        "Phải chỉ định cổng upstream",
	"upstream port must be 1-65535":                    "Cổng upstream phải từ 1 đến 65535",
	"invalid upstream address":                         "Địa chỉ upstream không hợp lệ",
}

var panelMessagePatternsVI = []struct {
	pattern *regexp.Regexp
	text    string
}{
	{regexp.MustCompile(`^WireGuard peer (\S+) created with address (\S+)\.$`), "Đã tạo peer WireGuard ${1} với địa chỉ ${2}."},
	{regexp.MustCompile(`^Peer (\S+) is now configured for Private network\. Update its device: download and import the new \.conf file or scan the new QR code, then reactivate the tunnel\.$`), "Peer ${1} hiện được cấu hình cho mạng riêng. Cập nhật thiết bị: tải và nhập tệp .conf mới hoặc quét mã QR mới, sau đó kích hoạt lại đường hầm."},
	{regexp.MustCompile(`^Peer (\S+) is now configured for Full tunnel\. Update its device: download and import the new \.conf file or scan the new QR code, then reactivate the tunnel\.$`), "Peer ${1} hiện được cấu hình cho đường hầm toàn phần. Cập nhật thiết bị: tải và nhập tệp .conf mới hoặc quét mã QR mới, sau đó kích hoạt lại đường hầm."},
	{regexp.MustCompile(`^rpctl (\S+) is already the latest release\.$`), "rpctl ${1} đã là bản phát hành mới nhất."},
	{regexp.MustCompile(`^rpctl updated successfully from (\S+) to (\S+)\. The Web Panel will restart shortly\.$`), "Đã cập nhật rpctl thành công từ ${1} lên ${2}. Bảng điều khiển sẽ sớm khởi động lại."},
	{regexp.MustCompile(`^latest GitHub release (\S+) is older than installed version (\S+)$`), "Bản phát hành GitHub mới nhất ${1} cũ hơn phiên bản đã cài đặt ${2}"},
	{regexp.MustCompile(`^(\S+) does not accept arguments$`), "${1} không chấp nhận tham số"},
	{regexp.MustCompile(`^(\S+) accepts only a peer name$`), "${1} chỉ chấp nhận tên peer"},
	{regexp.MustCompile(`^WireGuard peer (\S+) already exists$`), "Peer WireGuard ${1} đã tồn tại"},
	{regexp.MustCompile(`^WireGuard peer (\S+) does not exist$`), "Peer WireGuard ${1} không tồn tại"},
	{regexp.MustCompile(`^site (\S+) does not exist$`), "Trang web ${1} không tồn tại"},
}

// Translate only known message structure; leave diagnostic output and values intact.
func translatePanelMessage(message string) string {
	if cause, detail, ok := strings.Cut(message, "; restoring previous binary failed: "); ok {
		return translatePanelMessage(cause) + "; khôi phục tệp thực thi trước đó thất bại: " + detail
	}
	if cause, version, ok := strings.Cut(message, "; previous binary "); ok && strings.HasSuffix(version, " was restored") {
		return translatePanelMessage(cause) + "; đã khôi phục tệp thực thi phiên bản " + strings.TrimSuffix(version, " was restored")
	}
	if rest, ok := strings.CutPrefix(message, "ERROR:"); ok {
		return "Lỗi: " + translatePanelMessage(strings.TrimPrefix(rest, " "))
	}
	if rest, ok := strings.CutPrefix(message, "ERROR "); ok {
		return "Lỗi: " + translatePanelMessage(rest)
	}
	if message == "ERROR" {
		return "Lỗi"
	}
	if main, warning, ok := strings.Cut(message, " WARNING: "); ok {
		return translatePanelMessage(main) + " CẢNH BÁO: " + translatePanelMessage(warning)
	}
	if translated, ok := panelMessagesVI[message]; ok {
		return translated
	}
	for _, item := range panelMessagePatternsVI {
		if item.pattern.MatchString(message) {
			return item.pattern.ReplaceAllString(message, item.text)
		}
	}
	for _, item := range []struct{ english, vietnamese string }{
		{"connecting to privileged helper: ", "Kết nối đến dịch vụ đặc quyền: "},
		{"reading privileged helper response: ", "Đọc phản hồi từ dịch vụ đặc quyền: "},
		{"reading installed version: ", "Đọc phiên bản đã cài đặt: "},
		{"downloading release checksums: ", "Tải mã kiểm tra bản phát hành: "},
		{"downloading release binary: ", "Tải tệp thực thi bản phát hành: "},
		{"validating downloaded binary: ", "Xác thực tệp thực thi đã tải: "},
		{"saving previous binary: ", "Lưu tệp thực thi trước đó: "},
		{"installing update: ", "Cài đặt bản cập nhật: "},
		{"syncing installed update: ", "Đồng bộ bản cập nhật đã cài đặt: "},
		{"refreshing Web Panel units: ", "Làm mới các dịch vụ bảng điều khiển: "},
		{"checking Web Panel installation: ", "Kiểm tra cài đặt bảng điều khiển: "},
		{"update installed, but the Web Panel restart could not be scheduled", "Đã cài đặt bản cập nhật nhưng không thể lên lịch khởi động lại bảng điều khiển"},
		{"GitHub returned HTTP ", "GitHub trả về HTTP "},
		{"unsupported update architecture ", "Kiến trúc cập nhật không được hỗ trợ: "},
		{"invalid release version ", "Phiên bản phát hành không hợp lệ: "},
		{"SHA256SUMS does not contain a valid checksum for ", "SHA256SUMS không chứa mã kiểm tra hợp lệ cho "},
		{"reading Tailscale status: ", "Đọc trạng thái Tailscale: "},
		{"Tailscale executable is invalid: ", "Tệp thực thi Tailscale không hợp lệ: "},
		{"reading WireGuard server configuration: ", "Đọc cấu hình máy chủ WireGuard: "},
	} {
		if rest, ok := strings.CutPrefix(message, item.english); ok {
			return item.vietnamese + rest
		}
	}
	return message
}

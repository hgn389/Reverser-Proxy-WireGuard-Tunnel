package webpanel

import "testing"

func TestTranslatePanelMessage(t *testing.T) {
	tests := []struct{ message, want string }{
		{"", ""},
		{"Operation completed successfully.", "Thao tác hoàn tất thành công."},
		{"WireGuard peer phone-1 created with address 10.8.0.23/32.", "Đã tạo peer WireGuard phone-1 với địa chỉ 10.8.0.23/32."},
		{"rpctl v1.2.3 is already the latest release.", "rpctl v1.2.3 đã là bản phát hành mới nhất."},
		{"rpctl updated successfully from v1.2.3 to v1.2.4. The Web Panel will restart shortly. WARNING: update installed, but the Web Panel restart could not be scheduled: exit status 1", "Đã cập nhật rpctl thành công từ v1.2.3 lên v1.2.4. Bảng điều khiển sẽ sớm khởi động lại. CẢNH BÁO: Đã cài đặt bản cập nhật nhưng không thể lên lịch khởi động lại bảng điều khiển: exit status 1"},
		{"ERROR: VPN IP Local must be a whole number from 1 to 254", "Lỗi: VPN IP Local phải là số nguyên từ 1 đến 254"},
		{"ERROR: system update is unavailable", "Lỗi: Chức năng cập nhật hệ thống hiện không khả dụng"},
		{"wg_peer_list does not accept arguments", "wg_peer_list không chấp nhận tham số"},
		{"wg_peer_delete accepts only a peer name", "wg_peer_delete chỉ chấp nhận tên peer"},
		{"No certificate status was returned.", "Không nhận được trạng thái chứng chỉ."},
		{"The managed certificate file was not found.", "Không tìm thấy tệp chứng chỉ được quản lý."},
		{"Tailscale is not installed", "Tailscale chưa được cài đặt"},
		{"ERROR: connecting to privileged helper: dial unix /run/rpctl.sock: permission denied", "Lỗi: Kết nối đến dịch vụ đặc quyền: dial unix /run/rpctl.sock: permission denied"},
		{"downloading release checksums: Get https://github.com/a/b: context deadline exceeded", "Tải mã kiểm tra bản phát hành: Get https://github.com/a/b: context deadline exceeded"},
		{"latest GitHub release v1.2.3 is older than installed version v2.0.0", "Bản phát hành GitHub mới nhất v1.2.3 cũ hơn phiên bản đã cài đặt v2.0.0"},
		{"GitHub returned HTTP 503", "GitHub trả về HTTP 503"},
		{"ERROR: refreshing Web Panel units: exit status 1; previous binary v1.2.3 was restored", "Lỗi: Làm mới các dịch vụ bảng điều khiển: exit status 1; đã khôi phục tệp thực thi phiên bản v1.2.3"},
		{"installing update: permission denied; restoring previous binary failed: read-only file system", "Cài đặt bản cập nhật: permission denied; khôi phục tệp thực thi trước đó thất bại: read-only file system"},
		{"ERROR: nginx: [emerg] invalid port in /etc/nginx/conf.d/a.conf:42", "Lỗi: nginx: [emerg] invalid port in /etc/nginx/conf.d/a.conf:42"},
		{"ERROR permission denied", "Lỗi: permission denied"},
		{"ERROR", "Lỗi"},
		{"open /etc/wireguard/wg0.conf: permission denied", "open /etc/wireguard/wg0.conf: permission denied"},
		{"unrecognized operation message", "unrecognized operation message"},
		{"prefix Operation completed successfully.", "prefix Operation completed successfully."},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			if got := translatePanelMessage(tt.message); got != tt.want {
				t.Errorf("translatePanelMessage(%q) = %q, want %q", tt.message, got, tt.want)
			}
		})
	}
}

func TestTranslatePanelPeerModeMessage(t *testing.T) {
	for _, tt := range []struct{ mode, translated string }{
		{"Private network", "mạng riêng"},
		{"Full tunnel", "đường hầm toàn phần"},
	} {
		message := "Peer phone-1 is now configured for " + tt.mode + ". Update its device: download and import the new .conf file or scan the new QR code, then reactivate the tunnel."
		want := "Peer phone-1 hiện được cấu hình cho " + tt.translated + ". Cập nhật thiết bị: tải và nhập tệp .conf mới hoặc quét mã QR mới, sau đó kích hoạt lại đường hầm."
		if got := translatePanelMessage(message); got != want {
			t.Errorf("translatePanelMessage(%q) = %q, want %q", message, got, want)
		}
	}
}

# Kết quả nghiệm thu trực tiếp

Ngày chạy: 2026-10-15 (UTC)

Network: `evidence-channel`
Chaincode: `evidence` version `1.0`, sequence `3`, Org1MSP và Org2MSP đã approve.

## Checklist 20/20

### Danh tính và phân quyền

- [x] Thêm nhân viên tạo tài khoản ứng dụng thành công (`INV001`, `INV002`, `INV003`).
- [x] Nhân viên tương tác Fabric có certificate/private key riêng trong `.fabric-wallets/<enrollmentID>/msp`.
- [x] `accountStatus` và `fabricIdentityStatus` được lưu và thay đổi độc lập.
- [x] OBSERVER gọi API ANALYZE nhận HTTP `403`; gọi thẳng chaincode bằng Wallet OBSERVER cũng bị từ chối.
- [x] Khóa tài khoản khiến đăng nhập nhận `401`; revoke `INV003` tạo trạng thái Couch `REVOKED` và Ledger `INACTIVE/REVOKED`.

### Bằng chứng và hash

- [x] Đăng ký file tạo Evidence ID duy nhất.
- [x] SHA-256 được tính bằng cách đọc byte của file theo từng chunk.
- [x] File không đổi trả `MATCH` và commit VERIFY `VALID`.
- [x] File bị thêm dữ liệu trả `MISMATCH`, không báo VERIFIED giả.
- [x] Metadata phân biệt thiết bị vật lý, E01/RAW/DD, memory dump, executable, document, image, log và PCAP.

### Blockchain và Chain of Custody

- [x] Evidence `50d0f741f9c04ff498130bf372dc1586` được ghi bằng transaction `0f7c048562d7ca0459e9539f70e1215751c5270276c55fd4926a214a1a967ff1`.
- [x] Backend lưu commit status `VALID`; endpoint ledger đối chiếu lại transaction trong `QueryHistory`.
- [x] TRANSFER lưu `fromHolder=INV001`, `toHolder=INV002`; RECEIVE do INV002 xác nhận.
- [x] COLLECT, ACCESS, TRANSFER, RECEIVE, ANALYZE và VERIFY có actor, Fabric signer và thời gian.
- [x] Transaction ID, block number, block hash và previous block hash được đọc từ peer và hiển thị trong ledger audit.

### Báo cáo và kiểm thử

- [x] Báo cáo lấy evidence, verification và custody history từ backend/Fabric.
- [x] `NOT_VERIFIED`, `MATCH`, `MISMATCH` tách riêng với trạng thái `RECORDED/COLLECT`.
- [x] Báo cáo chứa kết quả hash, actor, signer, transaction ID, commit status và lịch sử bảo quản.
- [x] Fabric/CA lỗi trả lỗi HTTP và startup preflight thất bại; không chuyển sang trạng thái thành công giả.
- [x] Đã kiểm thử quyền, khóa tài khoản, revoke, ACCESS, TRANSFER, RECEIVE, ANALYZE, hash MATCH/MISMATCH và transaction bị từ chối.

## Giao dịch minh chứng

| Nghiệp vụ | Transaction ID | Kết quả |
|---|---|---|
| COLLECT document | `0f7c048562d7ca0459e9539f70e1215751c5270276c55fd4926a214a1a967ff1` | VALID |
| VERIFY MATCH | `966ab22d3cf56256306d2a4ef009f1d9d3fc1eabb8bd78a473873836f90a4aea` | VALID |
| VERIFY MISMATCH | `c9782f0fd7d62f437cacd0e4d87cdaaf578211aec13a1179659f3c20c8642cf8` | VALID |
| ACCESS | `d5c43a7e34b7d282a1fcefcf67f61ca82b5ee72a4419bbae5bca8bfa019dab04` | VALID |
| TRANSFER | `54a4dec88e1e5406089961c0f9cc1c6ca8711044c64bbc77ba1a83d38e989dd7` | VALID |
| RECEIVE | `de0d4d5015d8afcf437547e1874878e6b4e49419d72568ff8b894754c9d5cbf0` | VALID |
| ANALYZE | `08668b7b9f2ad7765c35a2fd13a59809c55c3b2e656fc2ce14e22e5dc57b9358` | VALID |
| COLLECT E01 fixture | `bc83c7f1b245d7a184cc781a2ce475e88f59535f13bc607c2c1d3a96fcd61d06` | VALID |
| VERIFY E01 MATCH | `c16d4d2464f9ddb50e6fdf3f259d3d7c7f0a0e5b47e7e4e579a93d30ed73f819` | VALID |

## Ghi chú kiến trúc

- File evidence được lưu off-chain; blockchain chỉ lưu hash, metadata và custody events.
- Block number, validation code, `blockHash` và `previousBlockHash` được truy xuất từ block chứa đúng Transaction ID qua QSCC.
- PDF báo cáo được ký PAdES-B-B bằng certificate/private key trong Fabric MSP của người xuất báo cáo.
- CA revoke được kết hợp với trạng thái `REVOKED` trong chaincode và CRL được publish vào channel MSP configuration; backend tự kiểm tra hạn CRL định kỳ.

## Trạng thái dữ liệu QA sau kiểm thử

- `INV001` và `INV002`: tài khoản ứng dụng đã `LOCKED` vì credential chỉ dùng cho nghiệm thu; Fabric identity vẫn `ACTIVE` để giữ khả năng đối chiếu chữ ký lịch sử.
- `INV003`: tài khoản `LOCKED`, Fabric identity `REVOKED`, Staff record trên Ledger `INACTIVE/REVOKED`.
- Evidence đầu tiên được cố ý sửa nội dung off-chain để duy trì mẫu `MISMATCH`; Evidence E01 fixture được giữ nguyên ở trạng thái `MATCH`.

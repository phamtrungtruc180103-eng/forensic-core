const app = document.querySelector('#app');
const nav = [...document.querySelectorAll('[data-view]')];
let evidence = [];
let projects = [];
let investigators = [];
let reports = [];
let relations = [];
let ledger = [];
let selectedRelationId = null;
let selected = null;
let selectedProjectSummary = null;
let workflowResult = null;
let currentView = 'projects';
let authUser = JSON.parse(localStorage.getItem('forensicUser') || 'null');
const nativeFetch = window.fetch.bind(window);
window.fetch = (input, init = {}) => {
  const headers = new Headers(init.headers || {});
  const token = localStorage.getItem('forensicToken');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return nativeFetch(input, { ...init, headers });
};

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const evidenceTypes = [['PHYSICAL_DEVICE','Thiết bị vật lý (USB, HDD, SSD)'],['DISK_IMAGE','Ảnh đĩa pháp chứng'],['MEMORY_DUMP','Ảnh bộ nhớ RAM'],['FILE','Tệp tin (DLL, EXE, PDF, JPG, ZIP...)'],['NETWORK_CAPTURE','Dữ liệu mạng (PCAP, PCAPNG)'],['LOG','Nhật ký hệ thống'],['OTHER','Loại khác']];
const evidenceTypeLabel = value => evidenceTypes.find(([type]) => type === value)?.[1] || value || 'FILE';
const icon = (name, size = 16) => { const paths = { brand:'M12 2l9 5v10l-9 5-9-5V7z', home:'M3 11l9-8 9 8v9H3z', folder:'M3 5h7l2 2h9v12H3z', users:'M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8M22 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75', file:'M6 2h9l3 3v17H6zM15 2v4h4', workflow:'M4 5h16M4 12h10M4 19h16M17 9l3 3-3 3', transfer:'M5 7h14M5 17h14M15 4l4 3-4 3M9 14l-4 3 4 3', graph:'M4 18l6-6 4 4 6-8M4 21h16', ledger:'M4 7h16v13H4zM4 7l2-4h12l2 4M8 11h8M8 15h8', blocks:'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z', report:'M5 3h14v18H5zM8 8h8M8 12h8M8 16h5', settings:'M12 8a4 4 0 100 8 4 4 0 000-8zM3 12h2m14 0h2M12 3v2m0 14v2M5.6 5.6L7 7m10 10l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4', search:'M11 19a8 8 0 115.7-2.3L21 21', play:'M8 5v14l11-7z', pause:'M7 5h3v14H7zM14 5h3v14h-3z', check:'M5 12l4 4L19 6', clock:'M12 7v5l3 2M21 12a9 9 0 11-18 0 9 9 0 0118 0'}; const aliases = {'◆':'brand','⌂':'home','▣':'folder','♟':'users','▤':'file','⌘':'graph','⬡':'blocks','▥':'report','⚙':'settings'}; const path = paths[aliases[name] || name] || paths.file; return `<svg class="icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${path}"/></svg>`; };
document.querySelectorAll('[data-icon]').forEach(node => { node.innerHTML = icon(node.dataset.icon); });
const title = (iconName, heading, sub, action = '') => `<div class="page-title"><div><h1><span class="title-icon">${icon(iconName)}</span>${heading}</h1><p>${sub}</p></div><div class="actions">${action}</div></div>`;
const btn = (text, primary = false) => `<button class="btn${primary ? ' primary' : ''}">${text}</button>`;
const state = (text, color = 'green') => `<span class="status ${color}">${escapeHtml(text)}</span>`;
const empty = text => `<p class="empty">${escapeHtml(text)}</p>`;
const stats = items => `<div class="stats">${items.map(item => `<div class="metric ${item[3] || ''}"><span class="metric-icon">${icon(item[0])}</span><label>${item[2]}</label><strong>${item[1]}</strong></div>`).join('')}</div>`;
const tableToolbar = () => `<div class="toolbar"><div class="search">${icon('search', 15)}<input placeholder="Tìm kiếm dữ liệu..."></div>${btn('Tìm kiếm', true)}</div>`;
const date = value => value ? new Date(value).toLocaleString('vi-VN') : '-';
function showAuth(mode = 'login') {
  const register = mode === 'register';
  const positions = [['INVESTIGATOR','Điều tra viên'],['ANALYST','Chuyên viên phân tích'],['SUPERVISOR','Người giám sát'],['OBSERVER','Quan sát viên']];
  if (!register) positions.unshift(['ADMIN','Quản trị viên']);
  const positionField = `<label>Vị trí<select name="position" required>${positions.map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}</select></label>`;
  document.body.classList.add('auth-mode');
  app.innerHTML = `<section class="auth-template"><div class="auth-hero"><div class="auth-brand"><span>${icon('brand', 22)}</span><strong>FORENSIC CORE</strong></div><div class="auth-hero-copy"><span class="auth-kicker">BLOCKCHAIN EVIDENCE PLATFORM</span><h1>Điều tra số<br>minh bạch và tin cậy.</h1><p>Nền tảng quản lý, xác thực và truy xuất chứng cứ số trên Blockchain.</p></div><div class="auth-hero-footer"><span class="auth-dot"></span> Hệ thống bảo mật · Ledger bất biến</div></div><div class="auth-content"><div class="auth-content-inner"><div class="auth-mobile-brand">${icon('brand', 24)} <strong>FORENSIC CORE</strong></div><span class="auth-kicker">CỔNG TRUY CẬP HỆ THỐNG</span><h2>${register ? 'Tạo tài khoản mới' : 'Chào mừng trở lại'}</h2><p class="auth-description">${register ? 'Đăng ký tài khoản nghiệp vụ. Tài khoản quản trị viên được cấp riêng.' : 'Đăng nhập theo vị trí nghiệp vụ của bạn để tiếp tục.'}</p><form id="authForm" class="action-form"><label>Tên đăng nhập<input name="username" autocomplete="username" placeholder="Nhập tên đăng nhập" required></label><label>Mật khẩu<input name="password" type="password" minlength="${register ? 12 : 1}" autocomplete="${register ? 'new-password' : 'current-password'}" placeholder="${register ? 'Tối thiểu 12 ký tự' : 'Nhập mật khẩu'}" required></label>${positionField}<button class="btn primary auth-submit">${register ? 'Tạo tài khoản' : 'Đăng nhập'} <span>→</span></button></form><button id="authSwitch" class="auth-switch">${register ? 'Đã có tài khoản? ' : 'Chưa có tài khoản? '}<b>${register ? 'Đăng nhập' : 'Tạo tài khoản'}</b></button><small class="auth-security">${icon('check', 13)} Kết nối được bảo vệ bằng JWT</small></div></div></section>`;
  document.querySelector('#authSwitch').onclick = () => showAuth(register ? 'login' : 'register');
  document.querySelector('#authForm').onsubmit = async event => {
    event.preventDefault();
    const response = await nativeFetch(`/api/auth/${register ? 'register' : 'login'}`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.fromEntries(new FormData(event.target))) });
    if (!response.ok) return notify(await responseError(response, 'Đăng nhập thất bại.'), true);
    const data = await response.json();
    localStorage.setItem('forensicToken', data.access_token);
    localStorage.setItem('forensicUser', JSON.stringify(data.user));
    authUser = data.user;
    updateUserHeader();
    await init();
  };
}
function updateUserHeader() {
  const userNode = document.querySelector('.dashboard-user');
  if (!userNode) return;
  userNode.innerHTML = `<span class="dashboard-avatar">${escapeHtml((authUser?.username || '?').slice(0, 1).toUpperCase())}</span><span><strong>${escapeHtml(authUser?.username || 'Chưa đăng nhập')}</strong><small>${escapeHtml(authUser?.position || authUser?.role || '')}</small></span><button id="logoutButton" title="Đăng xuất">⇥</button>`;
  document.querySelector('#logoutButton').onclick = () => { localStorage.removeItem('forensicToken'); localStorage.removeItem('forensicUser'); authUser = null; showAuth(); };
}
function openPasswordChange(required = false) {
  openModal(required ? 'Bắt buộc đổi mật khẩu' : 'Đổi mật khẩu', `<form id="passwordChangeForm" class="action-form"><p class="small-note">Mật khẩu mới phải có ít nhất 12 ký tự.</p><label>Mật khẩu hiện tại<input name="current_password" type="password" minlength="8" required></label><label>Mật khẩu mới<input name="new_password" type="password" minlength="12" required></label><button class="btn primary">Cập nhật mật khẩu</button></form>`);
  const close = document.querySelector('#actionModal .close');
  if (required && close) close.style.display = 'none';
  document.querySelector('#passwordChangeForm').onsubmit = async event => {
    event.preventDefault();
    const response = await fetch('/api/auth/change-password', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.fromEntries(new FormData(event.target))) });
    if (!response.ok) return notify(await responseError(response, 'Không thể đổi mật khẩu.'), true);
    const data = await response.json();
    authUser = data.user;
    localStorage.setItem('forensicUser', JSON.stringify(authUser));
    document.querySelector('#actionModal')?.remove();
    notify('Đã đổi mật khẩu thành công.');
  };
}

function projectView() {
  const rows = projects.map(project => { const evidenceCount = evidence.filter(item => item.caseID === project.projectID).length; const actions = authUser?.role === 'admin' ? `<button type="button" class="btn edit-project" data-project-id="${escapeHtml(project.projectID)}">Sửa</button><button type="button" class="btn delete-project" data-project-id="${escapeHtml(project.projectID)}">Xóa</button>` : 'Xem'; return `<tr class="project-row" data-project-id="${escapeHtml(project.projectID)}"><td><strong>${escapeHtml(project.projectID)}</strong></td><td class="folder">${icon('folder', 16)}</td><td><strong>${escapeHtml(project.name)}</strong><br><small>${escapeHtml(project.description)}</small></td><td>${evidenceCount}</td><td>${state(project.status, project.status === 'ACTIVE' ? 'green' : 'orange')}</td><td>${date(project.createdAt)}</td><td class="table-actions">${actions}</td></tr>`; }).join('');
  return `${title('folder','Quản lý dự án','Tạo, quản lý và theo dõi các dự án điều tra số',`${btn('+ Tạo dự án mới', true)} ${btn('+ Phân công thành viên')}`)}${stats([['folder',projects.length,'Tổng dự án'],['play',projects.filter(p => p.status === 'ACTIVE').length,'Đang hoạt động','green'],['pause',projects.filter(p => p.status === 'PAUSED').length,'Tạm dừng','orange'],['check',projects.filter(p => p.status === 'CLOSED').length,'Đã kết thúc','purple']])}<section class="panel">${tableToolbar()}${rows ? `<div class="table-wrap"><table><thead><tr><th>ID</th><th></th><th>Tên dự án</th><th>Chứng cứ</th><th>Trạng thái</th><th>Ngày tạo</th><th>Thao tác</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Chưa có dự án.')}</section>`;
}

function openProjectEdit(project) {
  if (!project) return;
  openModal('Sửa dự án', `<form id="projectEditForm" class="action-form"><label>Mã dự án<input value="${escapeHtml(project.projectID)}" readonly></label><label>Tên vụ việc<input name="name" value="${escapeHtml(project.name)}" required></label><label>Mô tả<input name="description" value="${escapeHtml(project.description)}"></label><label>Trạng thái<select name="status" required><option value="ACTIVE" ${project.status === 'ACTIVE' ? 'selected' : ''}>Đang hoạt động</option><option value="PAUSED" ${project.status === 'PAUSED' ? 'selected' : ''}>Tạm dừng</option><option value="CLOSED" ${project.status === 'CLOSED' ? 'selected' : ''}>Đã kết thúc</option></select></label><label>Tiến độ (%)<input name="progress" type="number" min="0" max="100" value="${Number(project.progress) || 0}" required></label><button class="btn primary">Lưu thay đổi</button></form>`);
  document.querySelector('#projectEditForm').onsubmit = async event => {
    event.preventDefault();
    const response = await fetch(`/api/projects/${encodeURIComponent(project.projectID)}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) });
    if (!response.ok) return notify(await responseError(response, 'Không thể sửa dự án.'), true);
    document.querySelector('#actionModal')?.remove();
    await refreshData();
    notify('Đã cập nhật dự án thành công.');
  };
}

async function deleteProject(project) {
  if (!project || !await confirmAction(`Xóa dự án ${project.projectID}?`)) return;
  const response = await fetch(`/api/projects/${encodeURIComponent(project.projectID)}`, { method: 'DELETE' });
  if (!response.ok) return notify(await responseError(response, 'Không thể xóa dự án.'), true);
  await refreshData();
  notify('Đã xóa dự án thành công.');
}

function projectSummaryView(summary) {
  const project = summary.project;
  const people = Object.fromEntries(investigators.map(person => [person.investigatorID, person.name]));
  const progress = Math.max(0, Math.min(100, Number(summary.progress) || 0));
  const members = summary.members.map(member => `<div class="mini-row"><span class="mini-avatar">${escapeHtml((people[member.investigatorID] || member.investigatorID || '?').slice(0, 1).toUpperCase())}</span><div><strong>${escapeHtml(people[member.investigatorID] || member.investigatorID || '-')}</strong><small>${escapeHtml(member.role || '-')}</small></div></div>`).join('');
  const activities = summary.activities.map(item => `<div class="mini-row"><span class="folder">${icon(item.action === 'TRANSFER' ? 'transfer' : item.action === 'ACCESS' ? 'users' : 'file', 14)}</span><div><strong>${escapeHtml(item.action || 'Cập nhật')}</strong><small>${escapeHtml(item.evidenceID || '')} · ${date(item.timestamp)}</small></div></div>`).join('');
  const responsible = summary.members.find(member => member.role === 'SUPERVISOR') || summary.members[0];
  return `${title('folder', escapeHtml(project.name || 'Chi tiết dự án'), 'Thông tin tổng quan và tiến độ điều tra', '<button class="btn" id="backToProjects">← Quay lại</button>')}<div class="project-summary-grid"><section class="panel card-pad"><div class="panel-title"><h2>Thông tin dự án </h2><span class="status ${project.status === 'ACTIVE' ? 'green' : project.status === 'CLOSED' ? 'purple' : 'orange'}">${escapeHtml(project.status || '-')}</span></div><div class="detail-grid"><div><span>Mã dự án</span><strong>${escapeHtml(project.projectID)}</strong></div><div><span>Tên vụ việc</span><strong>${escapeHtml(project.name)}</strong></div><div><span>Người tạo</span><strong>${escapeHtml(project.createdBy || project.creator || '-')}</strong></div><div><span>Người phụ trách</span><strong>${escapeHtml(project.responsible || (responsible && (people[responsible.investigatorID] || responsible.investigatorID)) || '-')}</strong></div></div><p class="small-note">${escapeHtml(project.description || 'Chưa có mô tả.')}</p></section><section class="panel card-pad"><div class="panel-title"><h2>Tiến độ điều tra</h2><strong>${progress}%</strong></div><div class="project-progress"><span style="width:${progress}%"></span></div><p class="small-note">Trạng thái: ${escapeHtml(project.status || '-')}</p></section><section class="panel card-pad"><div class="panel-title"><h2>Thống kê</h2></div><div class="stats project-summary-stats">${[['file',summary.evidenceCount,'Bằng chứng'],['users',summary.memberCount,'Thành viên'],['clock',summary.activities.length,'Hoạt động gần đây']].map(item => `<div class="metric"><span class="metric-icon">${icon(item[0])}</span><label>${item[2]}</label><strong>${item[1]}</strong></div>`).join('')}</div></section><section class="panel card-pad"><div class="panel-title"><h2>Merkle Tree dự án</h2><span class="status-tag" id="projectMerkleLeafCount">Đang tải...</span></div><div class="hash-box" id="projectMerkleRoot">Đang tính Merkle Root...</div><div id="projectMerkleLeaves" class="small-note"></div></section><section class="panel card-pad"><div class="panel-title"><h2>Thành viên dự án</h2></div>${members || empty('Chưa có thành viên.')}</section><section class="panel card-pad"><div class="panel-title"><h2>Hoạt động gần đây</h2></div>${activities || empty('Chưa có hoạt động.')}</section></div>`;
}

async function openProjectSummary(projectId) {
  const response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/summary`);
  if (!response.ok) return notify(await responseError(response, 'Không thể tải thông tin dự án.'), true);
  selectedProjectSummary = await response.json();
  app.innerHTML = projectSummaryView(selectedProjectSummary);
  app.querySelector('#backToProjects').onclick = () => { selectedProjectSummary = null; mount('projects'); };
  const merkleResponse = await fetch(`/api/projects/${encodeURIComponent(projectId)}/merkle`);
  if (!merkleResponse.ok) return notify(await responseError(merkleResponse, 'Không thể tải Merkle Tree.'), true);
  const merkle = await merkleResponse.json();
  app.querySelector('#projectMerkleLeafCount').textContent = `${merkle.leafCount} lá`;
  app.querySelector('#projectMerkleRoot').textContent = `Merkle Root: ${merkle.merkleRoot || 'Chưa có chứng cứ'}`;
  app.querySelector('#projectMerkleLeaves').innerHTML = merkle.leaves.map(leaf => `<div class="mini-row"><div><strong>${escapeHtml(leaf.evidenceID)} · ${escapeHtml(leaf.fileName)}</strong><small>Hash: ${escapeHtml(leaf.hash)}<br>Merkle Proof: ${escapeHtml(leaf.proof.map(step => `${step.position}:${step.hash}`).join(' | ') || 'Root trực tiếp')}</small></div></div>`).join('') || empty('Dự án chưa có chứng cứ để tạo Merkle Tree.');
}

function investigatorView() {
  const rows = investigators.map(person => { const accountStatus = person.accountStatus || person.status || 'UNKNOWN'; const fabricStatus = person.fabricIdentityStatus || 'NOT_PROVISIONED'; return `<tr><td><strong>${escapeHtml(person.investigatorID)}</strong></td><td><strong>${escapeHtml(person.enrollmentID || '-')}</strong><br><small>${escapeHtml(person.organization || '-')}</small></td><td><strong>${escapeHtml(person.name)}</strong></td><td>${escapeHtml(person.email)}</td><td>${escapeHtml(person.role)}</td><td>${state(accountStatus, accountStatus === 'ACTIVE' ? 'green' : 'orange')}</td><td>${state(fabricStatus, fabricStatus === 'ACTIVE' ? 'green' : 'orange')}</td><td class="table-actions"><button class="btn edit-investigator" data-investigator-id="${escapeHtml(person.investigatorID)}">Sửa</button>${authUser?.role === 'admin' && fabricStatus !== 'REVOKED' ? `<button class="btn lock-investigator" data-investigator-id="${escapeHtml(person.investigatorID)}">${accountStatus === 'ACTIVE' ? 'Khóa TK' : 'Mở TK'}</button><button class="btn delete-investigator" data-investigator-id="${escapeHtml(person.investigatorID)}">Thu hồi CA</button>` : ''}</td></tr>`; }).join('');
  return `${title('users','Quản Lý Nhân Viên','Quản lý tài khoản và danh tính Fabric',btn('+ Thêm nhân viên', true))}${stats([['users',investigators.length,'Tổng nhân viên'],['check',investigators.filter(p => (p.accountStatus || p.status) === 'ACTIVE').length,'Tài khoản hoạt động','green']])}<section class="panel">${tableToolbar()}${rows ? `<div class="table-wrap"><table><thead><tr><th>Mã nhân viên</th><th>Enrollment ID Fabric</th><th>Tên</th><th>Email</th><th>Vai trò</th><th>Tài khoản</th><th>Fabric Identity</th><th>Thao tác</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Chưa có nhân viên.')}</section>`;
}

function openInvestigatorEdit(investigator) {
  const roleOptions = [['INVESTIGATOR','Điều tra viên'],['ANALYST','Chuyên viên phân tích'],['SUPERVISOR','Người giám sát'],['OBSERVER','Quan sát viên']];
  openModal('Sửa nhân viên', `<form id="investigatorEditForm" class="action-form"><label>Họ tên<input name="name" value="${escapeHtml(investigator.name)}" required></label><label>Email<input name="email" type="email" value="${escapeHtml(investigator.email)}" required></label><label>Vai trò<select name="role" required>${roleOptions.map(([value, text]) => `<option value="${value}" ${investigator.role === value ? 'selected' : ''}>${text}</option>`).join('')}</select></label><label>Enrollment ID Fabric<input name="enrollmentID" value="${escapeHtml(investigator.enrollmentID || '')}" readonly required></label><label>Tổ chức Fabric<input name="organization" value="${escapeHtml(investigator.organization || 'Org1MSP')}" readonly required></label><p class="small-note">Enrollment ID và tổ chức được khóa sau khi identity đã được cấp trên Fabric CA.</p><button class="btn primary">Lưu thay đổi</button></form>`);
  document.querySelector('#investigatorEditForm').onsubmit = async event => {
    event.preventDefault();
    const response = await fetch(`/api/investigators/${encodeURIComponent(investigator.investigatorID)}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.fromEntries(new FormData(event.target))) });
    if (!response.ok) return notify(await responseError(response, 'Không thể sửa nhân viên.'), true);
    document.querySelector('#actionModal').remove();
    await refreshData();
    notify('Đã cập nhật nhân viên thành công.');
  };
}

async function deleteInvestigator(investigator) {
  if (!await confirmAction(`Thu hồi danh tính Fabric của ${investigator.name}?`)) return;
  const response = await fetch(`/api/investigators/${encodeURIComponent(investigator.investigatorID)}`, { method:'DELETE' });
  if (!response.ok) return notify(await responseError(response, 'Không thể xóa nhân viên.'), true);
  if (selected?.investigatorID === investigator.investigatorID) selected = null;
  await refreshData();
  notify('Đã thu hồi danh tính Fabric và khóa tài khoản thành công.');
}

async function toggleInvestigatorAccount(investigator) {
  const current = investigator.accountStatus || investigator.status;
  const account_status = current === 'ACTIVE' ? 'LOCKED' : 'ACTIVE';
  const response = await fetch(`/api/investigators/${encodeURIComponent(investigator.investigatorID)}/status`, { method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ account_status, revoke_fabric_identity:false }) });
  if (!response.ok) return notify(await responseError(response, 'Không thể đổi trạng thái tài khoản.'), true);
  await refreshData();
  notify(account_status === 'ACTIVE' ? 'Đã mở khóa tài khoản thành công.' : 'Đã khóa tài khoản thành công.');
}

function evidenceRows() {
  return evidence.map(item => `<tr data-evidence-id="${escapeHtml(item.evidenceID)}"><td><strong>${escapeHtml(item.evidenceID.slice(0, 10))}</strong></td><td><span class="mini-avatar">${icon('file', 14)}</span></td><td><strong>${escapeHtml(item.fileName)}</strong><br><small>${escapeHtml(evidenceTypeLabel(item.evidenceType))} · ${escapeHtml(item.sha256Hash?.slice(0, 15) || '')}</small></td><td>${escapeHtml(item.caseID)}</td><td>${escapeHtml(item.investigator)}</td><td>${date(item.timestamp)}</td><td>${state(item.verificationStatus || 'NOT_VERIFIED', item.verificationStatus === 'MATCH' ? 'green' : 'orange')}</td><td class="table-actions">${authUser?.role === 'admin' ? `<button type="button" class="btn edit-evidence" data-evidence-id="${escapeHtml(item.evidenceID)}">Sửa</button><button type="button" class="btn delete-evidence" data-evidence-id="${escapeHtml(item.evidenceID)}">Xóa</button>` : ''}</td></tr>`).join('');
}

function openEvidenceEdit(item) {
  if (!item) return;
  openModal('Sửa chứng cứ', `<form id="evidenceEditForm" class="action-form"><label>Evidence ID<input value="${escapeHtml(item.evidenceID)}" readonly></label><label>Loại chứng cứ<select name="evidence_type" required>${evidenceTypes.map(([type, label]) => `<option value="${type}" ${type === (item.evidenceType || 'FILE') ? 'selected' : ''}>${label}</option>`).join('')}</select></label><label>Dự án<select name="case_id" required>${projects.map(project => `<option value="${escapeHtml(project.projectID)}" ${project.projectID === item.caseID ? 'selected' : ''}>${escapeHtml(project.projectID)} - ${escapeHtml(project.name)}</option>`).join('')}</select></label><label>Người tạo<select name="investigator_id" required>${investigators.map(person => `<option value="${escapeHtml(person.investigatorID)}" ${person.investigatorID === item.investigator ? 'selected' : ''}>${escapeHtml(person.name)} (${escapeHtml(person.investigatorID)})</option>`).join('')}</select></label><button type="submit" class="btn primary">Lưu thay đổi</button></form>`);
  const form = document.querySelector('#actionModal #evidenceEditForm');
  form.onsubmit = async event => {
    event.preventDefault();
    const response = await fetch(`/api/evidence/${encodeURIComponent(item.evidenceID)}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(form))) });
    if (!response.ok) return notify(await responseError(response, 'Không thể sửa chứng cứ.'), true);
    document.querySelector('#actionModal')?.remove();
    await refreshData();
    notify('Đã cập nhật chứng cứ thành công.');
  };
}

async function deleteEvidence(item) {
  if (!item || !await confirmAction(`Xóa chứng cứ ${item.evidenceID}?`)) return;
  const response = await fetch(`/api/evidence/${encodeURIComponent(item.evidenceID)}`, { method: 'DELETE' });
  if (!response.ok) return notify(await responseError(response, 'Không thể xóa chứng cứ.'), true);
  if (selected?.evidenceID === item.evidenceID) selected = null;
  await refreshData();
  notify('Đã xóa chứng cứ thành công. Lịch sử lưu ký vẫn được giữ lại.');
}

function evidenceDetail() {
  if (!selected) return empty('Chọn một chứng cứ để xem chi tiết.');
  return `<div class="evidence-detail-grid"><div class="evidence-detail-info"><div class="panel-title"><h2>Chi tiết chứng cứ</h2><div class="actions detail-header-actions">${btn('Tải file')}<span class="status-slot">${state(selected.verificationStatus || 'NOT_VERIFIED', selected.verificationStatus === 'MATCH' ? 'green' : 'orange')}</span></div></div><div class="mini-row"><span class="folder">${icon('file', 14)}</span><div><strong>${escapeHtml(selected.evidenceID)}</strong><small>Loại: ${escapeHtml(evidenceTypeLabel(selected.evidenceType))}</small></div></div><p><b>Tên tệp:</b> ${escapeHtml(selected.fileName)}</p><p><b>Nguồn thu thập:</b> ${escapeHtml(selected.source || '-')}</p><p><b>Phương pháp:</b> ${escapeHtml(selected.acquisitionMethod || '-')}</p><p><b>Người thu thập:</b> ${escapeHtml(selected.investigator)}</p><p><b>Thời gian thu thập:</b> ${date(selected.collectedAt || selected.timestamp)}</p><div class="hash-box">Hash (SHA-256): ${escapeHtml(selected.sha256Hash)}</div><div class="actions detail-actions">${btn('Verify')} ${btn('ACCESS')} ${btn('TRANSFER')}</div></div><div class="evidence-history"><div class="panel-title"><h2>Lịch sử lưu ký</h2></div><div id="custodyHistory">${empty('Đang tải lịch sử...')}</div></div></div>`;
}

function evidenceView() {
  return `${title('file','Quản lý chứng cứ','Danh sách chứng cứ đã ghi nhận trong hệ thống',btn('+ Thêm chứng cứ', true))}<section class="panel">${tableToolbar()}${stats([['file',evidence.length,'Tổng chứng cứ'],['check',evidence.filter(e => e.verificationStatus === 'MATCH').length,'Hash MATCH','green'],['clock',evidence.filter(e => (e.verificationStatus || 'NOT_VERIFIED') === 'NOT_VERIFIED').length,'Chưa xác minh','orange']])}<div class="table-wrap">${evidence.length ? `<table><thead><tr><th>ID</th><th>Loại</th><th>Tên / Mô tả</th><th>Dự án</th><th>Người tạo</th><th>Thời gian</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>${evidenceRows()}</tbody></table>` : empty('Chưa có chứng cứ.')}</div></section>`;
}

function graphView() {
  const relationRows = relations.map(relation => `<div class="relation-row${selectedRelationId === relation.relationID ? ' selected' : ''}" data-relation-id="${escapeHtml(relation.relationID)}"><span><strong>${escapeHtml(relation.relation_type || relation.relation)}</strong> · ${escapeHtml(relation.from_evidence)} → ${escapeHtml(relation.to_evidence)}<small>${escapeHtml(relation.relation)}${relation.discovery_note ? ` · ${escapeHtml(relation.discovery_note)}` : ''}<br>${escapeHtml(relation.createdBy || '-')} · ${date(relation.createdAt)}</small></span></div>`).join('');
  const controls = `<div class="relation-toolbar"><button class="btn primary" id="addRelation">Thêm quan hệ</button><button class="btn" id="editRelation" ${selectedRelationId ? '' : 'disabled'}>Sửa</button>${authUser?.role === 'admin' ? `<button class="btn" id="deleteRelation" ${selectedRelationId ? '' : 'disabled'}>Xóa</button>` : ''}</div>`;
  return `${title('graph','Đồ thị chứng cứ','Hiển thị mối quan hệ giữa các chứng cứ', controls)}<section class="panel">${relations.length ? `<div class="graph-panel"><svg class="relationship-graph" role="img" aria-label="Đồ thị quan hệ chứng cứ"></svg></div>` : empty('Chưa có quan hệ chứng cứ.')}<div class="relation-list"><div class="panel-title"><h2>Quản lý quan hệ đồ thị</h2></div>${relationRows || '<p class="small-note">Chưa có quan hệ để chỉnh sửa hoặc xóa.</p>'}</div></section>`;
}

async function openGraphEvidenceDetail(evidenceId) {
  const item = evidence.find(record => record.evidenceID === evidenceId);
  if (!item) return;
  const response = await fetch(`/api/evidence/${encodeURIComponent(evidenceId)}/history`);
  const history = response.ok ? await response.json() : [];
  const related = relations.filter(relation => relation.from_evidence === evidenceId || relation.to_evidence === evidenceId);
  openModal('Chi tiết nút bằng chứng', `<div class="graph-evidence-detail"><div class="detail-grid"><div><span>Evidence ID</span><strong>${escapeHtml(item.evidenceID)}</strong></div><div><span>Loại</span><strong>${escapeHtml(item.evidenceType || 'File')}</strong></div><div><span>Tên</span><strong>${escapeHtml(item.fileName || '-')}</strong></div><div><span>Dự án</span><strong>${escapeHtml(item.caseID || '-')}</strong></div><div><span>Nguồn gốc</span><strong>${escapeHtml(item.source || item.investigator || '-')}</strong></div><div><span>Phát hiện lúc</span><strong>${date(item.timestamp)}</strong></div></div><div class="hash-box">SHA-256: ${escapeHtml(item.sha256Hash || '-')}</div><h3>Lịch sử bằng chứng</h3>${history.map(event => `<div class="mini-row"><div><strong>${escapeHtml(event.action || 'EVENT')}</strong><small>${date(event.timestamp)} · ${escapeHtml(event.investigator || event.actorID || '-')}</small></div></div>`).join('') || empty('Chưa có lịch sử.') }<h3>Quan hệ liên quan</h3>${related.map(relation => `<div class="mini-row"><div><strong>${escapeHtml(relation.relation_type || relation.relation)}</strong><small>${escapeHtml(relation.from_evidence)} → ${escapeHtml(relation.to_evidence)}</small></div></div>`).join('') || empty('Chưa có quan hệ.')}</div>`);
}

function ledgerView() {
  const rows = ledger.map(item => `<tr><td><button type="button" class="link-button ledger-verify" data-tx-id="${escapeHtml(item.txID || '')}">${escapeHtml((item.txID || '').slice(0, 14))}</button></td><td>${escapeHtml(item.blockNumber ?? '-')}</td><td title="${escapeHtml(item.blockHash || '')}">${escapeHtml((item.blockHash || '-').slice(0, 14))}</td><td>${escapeHtml(item.sha256Hash || '-')}</td><td>${escapeHtml(item.sender || item.investigator || '-')}</td><td>${escapeHtml(item.organization || '-')}</td><td>${date(item.timestamp)}</td><td>${state(item.transactionStatus || 'UNKNOWN', item.transactionStatus === 'VALID' ? 'green' : 'orange')}</td></tr>`).join('');
  return `${title('blocks','Ledger Blockchain','Theo dõi và kiểm tra các giao dịch ghi nhận chứng cứ',btn('Làm mới'))}<section class="panel">${rows ? `<div class="table-wrap"><table><thead><tr><th>Transaction ID</th><th>Block Number</th><th>Block Hash</th><th>Hash bằng chứng</th><th>Người gửi</th><th>Tổ chức xác thực</th><th>Thời điểm</th><th>Trạng thái</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Chưa có giao dịch hiển thị.')}</section>`;
}

async function verifyLedgerTransaction(transactionId) {
  const response = await fetch(`/api/ledger/${encodeURIComponent(transactionId)}`);
  if (!response.ok) return notify(await responseError(response, 'Không thể kiểm tra giao dịch.'), true);
  const result = await response.json();
  notify(result.valid ? 'Giao dịch hợp lệ và có trong lịch sử Fabric.' : `CẢNH BÁO: ${result.status || 'giao dịch không hợp lệ'}.`, !result.valid);
}

function reportsView() {
  const rows = reports.map(report => `<tr><td><button type="button" class="link-button report-detail" data-report-id="${escapeHtml(report.reportID)}">${escapeHtml(report.reportID)}</button></td><td>${escapeHtml(report.name)}</td><td>${escapeHtml(report.project_id)}</td><td>${state(report.status)}</td><td>${date(report.createdAt)}</td><td><button type="button" class="btn report-pdf" data-report-id="${escapeHtml(report.reportID)}">Xuất PDF</button></td></tr>`).join('');
  return `${title('report','Báo cáo và minh chứng','Danh sách bằng chứng, hash, Chain of Custody và giao dịch',btn('+ Tạo mới', true))}<section class="panel">${rows ? `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Tên</th><th>Dự án</th><th>Trạng thái</th><th>Ngày tạo</th><th>Thao tác</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Chưa có báo cáo.')}</section>`;
}

async function openReportDetail(reportId) {
  const response = await fetch(`/api/reports/${encodeURIComponent(reportId)}`);
  if (!response.ok) return notify(await responseError(response, 'Không thể tải báo cáo.'), true);
  const data = await response.json();
  const checks = Object.fromEntries(data.hashChecks.map(check => [check.evidenceID, check]));
  const evidenceRows = data.evidence.map(item => { const check = checks[item.evidenceID] || {status:'NOT_VERIFIED'}; return `<tr><td>${escapeHtml(item.evidenceID)}</td><td>${escapeHtml(item.fileName)}</td><td>${escapeHtml(item.sha256Hash)}</td><td>${state(check.status, check.status === 'MATCH' ? 'green' : 'orange')}<br><small>${escapeHtml(check.currentHash || '-')}</small></td></tr>`; }).join('');
  const custodyRows = data.custody.map(item => `<tr><td>${date(item.timestamp)}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.actorID || item.investigator || '-')}<br><small>Signer: ${escapeHtml(item.signerID || '-')}</small></td><td>${escapeHtml(item.txID || '-')}<br><small>${escapeHtml(item.transactionStatus || '-')}</small></td><td>${escapeHtml(item.blockNumber ?? '-')}</td></tr>`).join('');
  openModal(`Báo cáo ${escapeHtml(data.report.reportID)}`, `<div class="report-detail"><p><b>Dự án:</b> ${escapeHtml(data.project?.projectID || data.report.project_id)} - ${escapeHtml(data.project?.name || '-')}<br><b>Người lập:</b> ${escapeHtml(data.report.createdBy || '-')} · ${date(data.generatedAt)} UTC<br><b>Kết luận:</b> ${escapeHtml(data.conclusion)}<br><b>Giới hạn:</b> ${escapeHtml(data.limitations)}</p><h3>Danh sách bằng chứng và kết quả phân tích</h3><div class="table-wrap"><table><thead><tr><th>Evidence ID</th><th>Tệp</th><th>SHA-256 tham chiếu</th><th>Kết quả kiểm tra thực tế</th></tr></thead><tbody>${evidenceRows || '<tr><td colspan="4">Chưa có bằng chứng.</td></tr>'}</tbody></table></div><h3>Lịch sử Chain of Custody</h3><div class="table-wrap"><table><thead><tr><th>Thời điểm</th><th>Thao tác</th><th>Người thực hiện</th><th>Transaction ID</th><th>Block</th></tr></thead><tbody>${custodyRows || '<tr><td colspan="5">Chưa có lịch sử.</td></tr>'}</tbody></table></div><p class="small-note">Block Hash tham chiếu: ${escapeHtml(data.transactions[0]?.blockHash || 'Chưa có')}<br>Transaction ID và trạng thái VALID có thể đối chiếu trên Fabric.</p><button class="btn primary" id="downloadReportPdf">Xuất báo cáo PDF</button></div>`);
  document.querySelector('#downloadReportPdf').onclick = async () => { const pdfResponse = await fetch(`/api/reports/${encodeURIComponent(reportId)}/pdf`); if (!pdfResponse.ok) return notify(await responseError(pdfResponse, 'Không thể xuất PDF.'), true); const blob = await pdfResponse.blob(); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `${reportId}.pdf`; link.click(); URL.revokeObjectURL(link.href); };
}

function overviewView() {
  return `${title('home','Tổng quan','Tổng quan dữ liệu thực tế của hệ thống')}${stats([['file',evidence.length,'Chứng cứ'],['users',investigators.length,'Số Lượng Nhân Viên'],['folder',projects.length,'Dự án'],['report',reports.length,'Báo cáo']])}<section class="panel card-pad"><h2>Trạng thái Blockchain</h2><div class="detail-grid"><div><span>Network</span><strong>evidence-channel</strong></div><div><span>Ledger</span><strong>Fabric peer</strong></div><div><span>Chứng cứ</span><strong>${evidence.length}</strong></div></div></section>`;
}

function workflowView() {
  const result = workflowResult;
  const resultClass = result ? (result.valid ? 'workflow-success' : 'workflow-danger') : '';
  const resultContent = result ? `<div class="workflow-result ${resultClass}"><div class="workflow-result-heading"><span class="workflow-result-icon">${result.valid ? '✓' : '!'}</span><div><strong>${result.valid ? 'ĐÃ XÁC MINH NGUYÊN VẸN' : 'PHÁT HIỆN SAI LỆCH'}</strong><small>${result.valid ? 'HÀM BĂM KHỚP 100%' : 'SAI LỆCH HÀM BĂM'}</small></div><b>ID: ${escapeHtml(result.evidenceID)}</b></div><div class="hash-compare"><label>HÀM BĂM GỐC GHI NHẬN TRÊN BLOCKCHAIN</label><code>${escapeHtml(result.expectedHash || '-')}</code><label>${result.source === 'external' ? 'HÀM BĂM TỆP ĐỐI SOÁT BÊN NGOÀI' : 'HÀM BĂM TỆP ĐANG LƯU TRỮ'}</label><code class="${result.valid ? 'hash-match' : 'hash-mismatch'}">${escapeHtml(result.actualHash || '-')}</code></div><div class="workflow-actions"><button class="btn" id="workflowVerify">${result.source === 'external' ? 'Đối soát lại tệp đã chọn' : 'Kiểm tra tệp đang lưu trữ'}</button><button class="btn primary" id="workflowDownload">Tải tệp chứng cứ</button></div></div>` : empty('Nhập Evidence ID hoặc chọn một chứng cứ để bắt đầu xác minh.');
  const evidenceOptions = evidence.map(item => `<option value="${escapeHtml(item.evidenceID)}" ${item.evidenceID === selected?.evidenceID ? 'selected' : ''}>${escapeHtml(item.evidenceID)} - ${escapeHtml(item.fileName || 'Chứng cứ')}</option>`).join('');
  return `${title('blocks','Quy Trình Điều Tra Số','Tra cứu, xác minh tính toàn vẹn và theo dõi hồ sơ chứng cứ')}<section class="workflow-search panel"><select id="workflowEvidenceId" required><option value="">Chọn Evidence ID</option>${evidenceOptions}</select><button class="btn primary" id="workflowSearch">${icon('search', 15)} Tra cứu</button></section><div class="workflow-result-area">${resultContent}</div><div class="workflow-profile-grid"><section class="panel workflow-profile"><div class="panel-title"><h2>Hồ sơ bằng chứng số</h2><span class="status-tag">${escapeHtml(selected?.evidenceID || '-')}</span></div>${selected ? `<div class="workflow-facts"><p><span>Chuyên án:</span><b>${escapeHtml(selected.caseID)}</b></p><p><span>Tên tệp chứng cứ:</span><b>${escapeHtml(selected.fileName)}</b></p><p><span>Loại chứng cứ:</span><b>${escapeHtml(evidenceTypeLabel(selected.evidenceType))}</b></p><p><span>Người đăng ký:</span><b>${escapeHtml(selected.investigator)}</b></p><p><span>Thời điểm ghi nhận:</span><b>${date(selected.timestamp)}</b></p><p><span>Hash SHA-256:</span><b class="break">${escapeHtml(selected.sha256Hash)}</b></p></div>` : empty('Chưa chọn chứng cứ.')}</section><section class="panel workflow-history"><div class="panel-title"><h2>Lịch sử lưu ký</h2></div><div id="custodyHistory">${selected ? empty('Đang tải lịch sử...') : empty('Chưa chọn chứng cứ.')}</div></section><section class="panel workflow-external"><h2>Kiểm tra đối soát với tệp tin vật lý bên ngoài</h2><p>Tải lên một tệp bất kỳ để tính SHA-256 và so khớp với hàm băm đã ghi nhận trên hệ thống.</p><label class="file-picker"><input id="workflowFile" type="file"> Chọn tệp kiểm tra đối soát</label><div id="workflowFileStatus" class="small-note">Chưa chọn tệp.</div></section></div>`;
}

function transferView() {
  const rows = evidence.map(item => `<tr class="${selected?.evidenceID === item.evidenceID ? 'selected-row' : ''}" data-transfer-evidence-id="${escapeHtml(item.evidenceID)}"><td><strong>${escapeHtml(item.evidenceID.slice(0, 14))}</strong></td><td>${escapeHtml(item.fileName)}</td></tr>`).join('');
  const details = selected ? `<div class="transfer-detail-card"><div class="panel-title"><h2>Chi tiết chứng cứ</h2>${state(selected.verificationStatus || 'NOT_VERIFIED', selected.verificationStatus === 'MATCH' ? 'green' : 'orange')}</div><div class="mini-row"><span class="folder">${icon('file', 14)}</span><div><strong>${escapeHtml(selected.evidenceID)}</strong><small>Loại: ${escapeHtml(evidenceTypeLabel(selected.evidenceType))}</small></div></div><p><b>Tên tệp:</b> ${escapeHtml(selected.fileName)}</p><p><b>Người tạo:</b> ${escapeHtml(selected.investigator)}</p><p><b>Người giữ hiện tại:</b> ${escapeHtml(selected.currentHolder || selected.investigator)}</p><p><b>Thời gian tạo:</b> ${date(selected.timestamp)}</p><div class="hash-box">Hash (SHA-256): ${escapeHtml(selected.sha256Hash)}</div><div class="transfer-action-bar"><button type="button" class="btn" id="transferDownload">Tải file</button><button type="button" class="btn" id="transferVerify">VERIFY</button><button type="button" class="btn" id="transferAccess">ACCESS</button><button type="button" class="btn" id="transferReceive">RECEIVE</button><button type="button" class="btn" id="transferAnalyze">ANALYZE</button><button type="button" class="btn primary" id="transferOpenForm">TRANSFER</button></div></div>` : empty('Chọn một chứng cứ để xem chi tiết và ghi nhận chuyển giao.');
  return `${title('blocks','Chuyển Giao Chứng Cứ','Ghi nhận việc bàn giao chứng cứ và lưu vết trên Blockchain')}<div class="transfer-workflow-grid"><section class="panel transfer-evidence-list"><div class="panel-title card-pad"><h2>Tiến trình chứng cứ</h2><small>Chọn một dòng để thực hiện nghiệp vụ</small></div>${rows ? `<div class="table-wrap"><table><thead><tr><th>Evidence ID</th><th>Tên tệp</th></tr></thead><tbody>${rows}</tbody></table></div>` : empty('Chưa có chứng cứ.')}</section><section class="panel transfer-detail-panel">${details}</section><section class="panel transfer-history-panel"><div class="panel-title"><h2>Lịch sử lưu ký</h2></div><div id="custodyHistory">${selected ? empty('Đang tải lịch sử...') : empty('Chưa chọn chứng cứ.')}</div></section></div>`;
}

const views = { overview: overviewView, projects: projectView, investigators: investigatorView, evidence: evidenceView, workflow: workflowView, transfer: transferView, graph: graphView, ledger: ledgerView, reports: reportsView, settings: () => `${title('settings','Cài đặt hệ thống','Bảo mật tài khoản và cấu hình hệ thống')}<section class="panel card-pad"><h2>Bảo mật tài khoản</h2><p>JWT sử dụng secret riêng được lưu với quyền 0600. Mật khẩu không có giá trị mặc định.</p><button class="btn primary" id="changePasswordButton">Đổi mật khẩu</button></section>` };
function mount(view = 'projects') {
  if (!localStorage.getItem('forensicToken') || !authUser) {
    return showAuth();
  }
  document.body.classList.remove('auth-mode');
  currentView = view;
  nav.forEach(item => item.classList.toggle('active', item.dataset.view === view));
  app.innerHTML = views[view]();
  app.querySelectorAll('[data-evidence-id]').forEach(row => row.addEventListener('click', () => { selected = evidence.find(item => item.evidenceID === row.dataset.evidenceId); mount(currentView); }));
  app.querySelectorAll('.project-row').forEach(row => row.addEventListener('click', () => openProjectSummary(row.dataset.projectId)));
  bindActions();
  app.querySelector('#changePasswordButton')?.addEventListener('click', () => openPasswordChange(false));
  app.querySelectorAll('.edit-investigator').forEach(button => button.onclick = () => openInvestigatorEdit(investigators.find(item => item.investigatorID === button.dataset.investigatorId)));
  app.querySelectorAll('.lock-investigator').forEach(button => button.onclick = () => toggleInvestigatorAccount(investigators.find(item => item.investigatorID === button.dataset.investigatorId)));
  app.querySelectorAll('.delete-investigator').forEach(button => button.onclick = () => deleteInvestigator(investigators.find(item => item.investigatorID === button.dataset.investigatorId)));
  app.querySelectorAll('.edit-evidence').forEach(button => button.onclick = event => { event.stopPropagation(); openEvidenceEdit(evidence.find(item => item.evidenceID === button.dataset.evidenceId)); });
  app.querySelectorAll('.delete-evidence').forEach(button => button.onclick = event => { event.stopPropagation(); deleteEvidence(evidence.find(item => item.evidenceID === button.dataset.evidenceId)); });
  app.querySelectorAll('.edit-project').forEach(button => button.onclick = event => { event.stopPropagation(); openProjectEdit(projects.find(item => item.projectID === button.dataset.projectId)); });
  app.querySelectorAll('.delete-project').forEach(button => button.onclick = event => { event.stopPropagation(); deleteProject(projects.find(item => item.projectID === button.dataset.projectId)); });
  if (view === 'graph') renderGraph();
  if ((view === 'evidence' || view === 'workflow' || view === 'transfer') && selected) loadHistory();
  if (view === 'workflow') bindWorkflow();
  if (view === 'transfer') bindTransfer();
  if (view === 'graph') {
    app.querySelector('#addRelation')?.addEventListener('click', openRelationForm);
    app.querySelector('#editRelation')?.addEventListener('click', () => openRelationEdit(relations.find(item => item.relationID === selectedRelationId)));
    app.querySelector('#deleteRelation')?.addEventListener('click', () => deleteRelation(relations.find(item => item.relationID === selectedRelationId)));
    app.querySelectorAll('.relation-row').forEach(row => row.addEventListener('click', () => {
      selectedRelationId = row.dataset.relationId;
      mount('graph');
    }));
    app.querySelectorAll('.graph-node').forEach(node => node.addEventListener('click', () => openGraphEvidenceDetail(node.dataset.id)));
  }
  function bindTransfer() {
    app.querySelectorAll('[data-transfer-evidence-id]').forEach(row => row.addEventListener('click', () => {
      selected = evidence.find(item => item.evidenceID === row.dataset.transferEvidenceId) || null;
      mount('transfer');
    }));
    document.querySelector('#transferDownload')?.addEventListener('click', downloadSelected);
    document.querySelector('#transferVerify')?.addEventListener('click', verifySelected);
    document.querySelector('#transferAccess')?.addEventListener('click', () => openCustody('access'));
    document.querySelector('#transferReceive')?.addEventListener('click', openReceive);
    document.querySelector('#transferAnalyze')?.addEventListener('click', openAnalyze);
    document.querySelector('#transferOpenForm')?.addEventListener('click', () => openCustody('transfer'));
  }
}
function bindWorkflow() {
  const search = document.querySelector('#workflowSearch');
  const input = document.querySelector('#workflowEvidenceId');
  search?.addEventListener('click', () => {
    const id = input.value.trim();
    selected = evidence.find(item => item.evidenceID === id) || null;
    workflowResult = null;
    if (!selected) return notify('Không tìm thấy Evidence ID này.', true);
    mount('workflow');
  });
  document.querySelector('#workflowVerify')?.addEventListener('click', () => verifyWorkflow());
  document.querySelector('#workflowDownload')?.addEventListener('click', () => downloadSelected());
  document.querySelector('#workflowFile')?.addEventListener('change', async event => {
    const file = event.target.files?.[0];
    const status = document.querySelector('#workflowFileStatus');
    if (!file || !selected) return;
    status.textContent = 'Đang tính hàm băm SHA-256...';
    const actualHash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    const valid = actualHash.toLowerCase() === String(selected.sha256Hash || '').toLowerCase();
    workflowResult = { evidenceID: selected.evidenceID, expectedHash: selected.sha256Hash, actualHash, valid, source: 'external' };
    status.textContent = valid ? 'MATCH 100% - Tệp khớp với chứng cứ đã ghi nhận.' : 'HASH MISMATCH - Tệp không khớp.';
    mount('workflow');
  });
}
async function verifyWorkflow() {
  if (!selected) return notify('Hãy chọn một Evidence ID trước.', true);
  if (workflowResult?.source === 'external') {
    notify(workflowResult.valid ? 'Tệp đối soát khớp 100% với chứng cứ gốc.' : 'Tệp đối soát không khớp với chứng cứ gốc.', !workflowResult.valid);
    return;
  }
  const response = await fetch(`/api/evidence/${encodeURIComponent(selected.evidenceID)}/verify`, { method:'POST' });
  if (!response.ok) return notify(await responseError(response, 'Không thể xác minh chứng cứ.'), true);
  const result = await response.json();
  workflowResult = { ...result, expectedHash: result.expectedHash || result.expectedSHA256 || selected.sha256Hash, actualHash: result.actualHash || result.actualSHA256 || result.currentHash };
  mount('workflow');
}
function renderGraph() {
  const svg = document.querySelector('.relationship-graph');
  if (!svg) return;
  const width = Math.max(svg.parentElement.clientWidth, 450);
  const positions = new Map();
  const treeRelations = relations.filter(relation => relation.relation_type === 'PARENT_CHILD');
  const children = new Map(evidence.map(item => [item.evidenceID, []]));
  const childIds = new Set();
  treeRelations.forEach(relation => {
    if (!children.has(relation.from_evidence) || !children.has(relation.to_evidence)) return;
    children.get(relation.from_evidence).push(relation.to_evidence);
    childIds.add(relation.to_evidence);
  });
  const roots = treeRelations.length ? evidence.filter(item => !childIds.has(item.evidenceID)) : [];
  const levels = [];
  const visited = new Set();
  const placeTree = (id, level) => {
    if (visited.has(id)) return;
    visited.add(id);
    (levels[level] ||= []).push(id);
    (children.get(id) || []).forEach(child => placeTree(child, level + 1));
  };
  roots.forEach(root => placeTree(root.evidenceID, 0));
  evidence.forEach(item => { if (!visited.has(item.evidenceID)) placeTree(item.evidenceID, levels.length || 0); });
  const height = Math.max(450, levels.length * 120 + 60);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  if (treeRelations.length) {
    levels.forEach((level, levelIndex) => {
      const gap = width / (level.length + 1);
      level.forEach((id, index) => positions.set(id, { x: gap * (index + 1), y: 60 + levelIndex * 110 }));
    });
  } else {
    evidence.forEach((item, index) => positions.set(item.evidenceID, { x: 90 + (index % 4) * ((width - 180) / 3), y: 90 + Math.floor(index / 4) * 150 }));
  }
  const edges = relations.map(relation => ({
    source: positions.get(relation.from_evidence),
    target: positions.get(relation.to_evidence),
    label: relation.relation || 'related'
  })).filter(edge => edge.source && edge.target);
  svg.innerHTML = `<defs><marker id="graph-arrow" markerWidth="7" markerHeight="7" refX="7" refY="3.5" orient="auto"><path d="M0 0L7 3.5L0 7z" fill="#86a8c9"/></marker></defs>${edges.map(edge => `<line class="graph-edge" x1="${edge.source.x}" y1="${edge.source.y}" x2="${edge.target.x}" y2="${edge.target.y}" marker-end="url(#graph-arrow)"><title>${escapeHtml(edge.label)}</title></line>`).join('')}${evidence.map(item => { const p = positions.get(item.evidenceID); return `<g class="graph-node" data-id="${escapeHtml(item.evidenceID)}" transform="translate(${p.x} ${p.y})" tabindex="0"><rect x="-85" y="-42" width="170" height="84" rx="8"></rect><text class="graph-node-id" text-anchor="middle" y="-20">${escapeHtml(item.evidenceID.slice(0, 14))}</text><text class="graph-node-name" text-anchor="middle" y="-3">${escapeHtml(evidenceTypeLabel(item.evidenceType).slice(0, 22))}</text><text class="graph-node-name" text-anchor="middle" y="14">${escapeHtml((item.sha256Hash || '').slice(0, 18))}</text><text class="graph-node-name" text-anchor="middle" y="31">${escapeHtml(item.verificationStatus || 'NOT_VERIFIED')}</text></g>`; }).join('')}`;
  let dragged = null;
  svg.querySelectorAll('.graph-node').forEach(node => {
    node.addEventListener('pointerdown', event => { dragged = { node, startX: event.clientX, startY: event.clientY, x: positions.get(node.dataset.id).x, y: positions.get(node.dataset.id).y }; node.setPointerCapture(event.pointerId); });
    node.addEventListener('pointermove', event => { if (!dragged || dragged.node !== node) return; const scale = width / svg.getBoundingClientRect().width; const p = positions.get(node.dataset.id); p.x = dragged.x + (event.clientX - dragged.startX) * scale; p.y = dragged.y + (event.clientY - dragged.startY) * scale; node.setAttribute('transform', `translate(${p.x} ${p.y})`); edges.forEach(edge => { if (edge.source === p) { const line = edge.sourceLine; } }); renderGraphEdges(svg, edges); });
    node.addEventListener('pointerup', () => { dragged = null; });
  });
  renderGraphEdges(svg, edges);
}
function renderGraphEdges(svg, edges) { [...svg.querySelectorAll('.graph-edge')].forEach((line, index) => { const edge = edges[index]; if (edge) { line.setAttribute('x1', edge.source.x); line.setAttribute('y1', edge.source.y); line.setAttribute('x2', edge.target.x); line.setAttribute('y2', edge.target.y); } }); }
function notify(message, error = false) {
  let toast = document.querySelector('#toast');
  if (!toast) { toast = document.createElement('div'); toast.id = 'toast'; toast.className = 'toast'; toast.setAttribute('role', 'alert'); toast.setAttribute('aria-live', 'assertive'); document.body.append(toast); }
  toast.textContent = friendlyError(message); toast.style.background = error ? '#b33b49' : '#143b67'; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3000);
}
function confirmAction(message) {
  return new Promise(resolve => {
    const modal = document.createElement('div');
    modal.className = 'action-modal confirm-modal';
    modal.innerHTML = `<div class="action-card"><div class="panel-title"><h2>Xác nhận thao tác</h2></div><p class="confirm-message">${escapeHtml(message)}</p><div class="confirm-actions"><button type="button" class="btn" data-confirm-cancel>Hủy</button><button type="button" class="btn primary" data-confirm-ok>Xác nhận</button></div></div>`;
    document.body.append(modal);
    const finish = value => { modal.remove(); resolve(value); };
    modal.querySelector('[data-confirm-cancel]').onclick = () => finish(false);
    modal.querySelector('[data-confirm-ok]').onclick = () => finish(true);
    modal.addEventListener('click', event => { if (event.target === modal) finish(false); });
  });
}
function friendlyError(message) {
  const normalize = value => {
    if (Array.isArray(value)) return value.map(item => normalize(item)).filter(Boolean).join('; ');
    if (value && typeof value === 'object') {
      const location = Array.isArray(value.loc) ? value.loc.filter(Boolean).join(' → ') : '';
      return [location, value.msg || value.message || value.detail].filter(Boolean).join(': ');
    }
    return String(value || '');
  };
  const text = normalize(message);
  if (text.includes('MVCC_READ_CONFLICT')) return 'Giao dịch bị trùng thời điểm cập nhật. Dữ liệu chứng cứ vừa được thay đổi; hãy tải lại chứng cứ rồi thử lại.';
  if (text.includes('Fabric invoke failed')) return 'Không thể ghi giao dịch lên Blockchain. Vui lòng thử lại sau.';
  if (text.includes('Fabric CA enrollment failed')) return 'Không thể cấp danh tính Fabric cho nhân viên. Vui lòng kiểm tra Enrollment ID và trạng thái Fabric CA.';
  if (text.includes('Please execute enroll command first')) return 'Fabric CA chưa sẵn sàng cấp danh tính. Vui lòng khởi động lại dịch vụ rồi thử lại.';
  if (text.includes('identity already exists locally')) return 'Danh tính Fabric này đã tồn tại trên máy chủ. Hãy dùng Enrollment ID khác.';
  if (text.includes('Invalid Fabric enrollment ID')) return 'Enrollment ID Fabric không hợp lệ.';
  if (text.includes('staff already exists')) return 'Mã nhân viên đã tồn tại trên Fabric. Hệ thống sẽ tự chọn mã mới, hãy thử lại.';
  if (text.includes('Enrollment ID already exists')) return 'Enrollment ID này đã được sử dụng. Hãy nhập một Enrollment ID khác.';
  if (text.includes('Invalid or expired token')) return 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.';
  if (text.includes('Not authenticated')) return 'Bạn chưa đăng nhập hoặc phiên đăng nhập đã hết hạn.';
  if (text.includes('Incorrect username or password')) return 'Tên đăng nhập hoặc mật khẩu không đúng.';
  if (text.includes('Could not validate credentials')) return 'Thông tin đăng nhập không hợp lệ.';
  if (text.includes('Username already exists')) return 'Tên đăng nhập đã tồn tại. Vui lòng chọn tên khác.';
  if (text.includes('password must contain at least')) return 'Mật khẩu phải có ít nhất 8 ký tự.';
  if (text.includes('New password must contain at least')) return 'Mật khẩu mới phải có ít nhất 12 ký tự.';
  if (text.includes('Current password is incorrect')) return 'Mật khẩu hiện tại không đúng.';
  if (text.includes('Project not found')) return 'Không tìm thấy dự án đã chọn.';
  if (text.includes('Evidence not found')) return 'Không tìm thấy chứng cứ.';
  if (text.includes('Investigator not found')) return 'Không tìm thấy nhân viên.';
  if (text.includes('already exists')) return 'Dữ liệu đã tồn tại. Vui lòng kiểm tra lại thông tin.';
  if (text.includes('required')) return 'Vui lòng nhập đầy đủ các trường bắt buộc.';
  if (text.includes('Field required')) return 'Vui lòng nhập đầy đủ các trường bắt buộc.';
  if (text.includes('Network Error') || text.includes('Failed to fetch')) return 'Không thể kết nối đến máy chủ. Vui lòng thử lại.';
  if (/^HTTP \d+/i.test(text)) return 'Máy chủ trả về lỗi. Vui lòng thử lại hoặc liên hệ quản trị viên.';
  if (text.includes('Input should be') && text.includes('ACTIVE')) return 'Trạng thái dự án chỉ được chọn: Đang hoạt động, Tạm dừng hoặc Đã kết thúc.';
  return text || 'Đã xảy ra lỗi. Vui lòng thử lại.';
}
async function responseError(response, fallback = 'Đã xảy ra lỗi. Vui lòng thử lại.') {
  try { return friendlyError((await response.json()).detail || fallback); } catch { return fallback; }
}
async function loadHistory() {
  try {
    const history = await fetch(`/api/evidence/${selected.evidenceID}/history`).then(response => response.json());
    const actionLabels = { COLLECT: 'Ghi nhận', CREATE: 'Tạo chứng cứ', ACCESS: 'Truy cập', TRANSFER: 'Chuyển giao', RECEIVE: 'Tiếp nhận', ANALYZE: 'Phân tích', VERIFY: 'Xác minh' };
    const detail = (label, value) => `<div><span>${label}</span><strong>${escapeHtml(value || '-')}</strong></div>`;
    document.querySelector('#custodyHistory').innerHTML = history.map((item, index) => `<article class="custody-event" data-history-index="${index}"><button type="button" class="custody-event-title"><span>${date(item.timestamp)} · ${escapeHtml(actionLabels[item.action] || item.action || 'Sự kiện')}</span><b>⌄</b></button><div class="custody-event-summary">Người thực hiện: ${escapeHtml(item.actorID || item.investigator || '-')} · Trạng thái: ${escapeHtml(item.transactionStatus || item.result || '-')}</div><div class="custody-event-details">${detail('Evidence ID', item.evidenceID)}${detail('Người thực hiện', item.actorID || item.investigator)}${detail('Bên giao', item.fromHolder)}${detail('Bên nhận', item.toHolder)}${detail('Lý do', item.reason)}${detail('Kết quả', item.result)}${detail('SHA-256', item.sha256Hash)}${detail('Merkle Root', item.merkleRoot)}${detail('Transaction ID', item.txID)}${detail('Block Number', item.blockNumber)}${detail('Block Hash', item.blockHash)}${detail('Người ký Fabric', item.signerID)}${detail('Tổ chức Fabric', item.signerMSP || item.organization)}${detail('Trạng thái giao dịch', item.transactionStatus)}</div></article>`).join('') || empty('Chưa có lịch sử.');
    document.querySelectorAll('.custody-event-title').forEach(button => button.addEventListener('click', () => {
      const event = button.closest('.custody-event');
      event.classList.toggle('expanded');
      button.querySelector('b').textContent = event.classList.contains('expanded') ? '⌃' : '⌄';
    }));
  } catch { document.querySelector('#custodyHistory').innerHTML = empty('Không thể tải lịch sử.'); }
}
function openModal(heading, body) { const modal = document.createElement('div'); modal.id = 'actionModal'; modal.className = 'action-modal'; modal.innerHTML = `<div class="action-card"><div class="panel-title"><h2>${heading}</h2><button class="close">×</button></div>${body}</div>`; document.body.append(modal); const status = modal.querySelector('input[name="status"]'); if (status) status.outerHTML = '<select name="status" required><option value="ACTIVE">Đang hoạt động</option><option value="PAUSED">Tạm dừng</option><option value="CLOSED">Đã kết thúc</option></select>'; modal.querySelector('.close').onclick = () => modal.remove(); }
function openUpload() {
  const projectOptions = projects.map(project => `<option value="${escapeHtml(project.projectID)}">${escapeHtml(project.projectID)} - ${escapeHtml(project.name)}</option>`).join('');
  const investigatorOptions = investigators
    .filter(person => (person.accountStatus || person.status) === 'ACTIVE' && (person.fabricIdentityStatus || person.status) === 'ACTIVE')
    .map(person => `<option value="${escapeHtml(person.investigatorID)}">${escapeHtml(person.investigatorID)} - ${escapeHtml(person.name)}</option>`).join('');
  const typeOptions = evidenceTypes.map(([type, label]) => `<option value="${type}">${label}</option>`).join('');
  if (!projectOptions || !investigatorOptions) return notify('Cần có vụ án và nhân viên có identity Fabric hoạt động.', true);
  openModal('Ghi nhận chứng cứ', `<form id="uploadActionForm" class="action-form"><label>Vụ án<select name="case_id" required>${projectOptions}</select></label><label>Loại chứng cứ<select name="evidence_type" required>${typeOptions}</select></label><label>Người thu thập<select name="investigator_id" required>${investigatorOptions}</select></label><label>Nguồn thu thập<input name="source" maxlength="500" placeholder="Thiết bị, vị trí hoặc nguồn dữ liệu" required></label><label>Phương pháp thu thập<input name="acquisition_method" maxlength="500" placeholder="Ví dụ: write blocker + FTK Imager" required></label><label>Thời gian thu thập<input name="collected_at" type="datetime-local" required></label><label>Tệp/ảnh pháp chứng<input name="file" type="file" required></label><div class="upload-progress" aria-live="polite"><div class="progress-track"><span></span></div><strong>0%</strong></div><button class="btn primary">Tải lên, tính SHA-256 và ghi Fabric</button></form>`);
  document.querySelector('#uploadActionForm').onsubmit = event => {
    event.preventDefault();
    const form = event.target, xhr = new XMLHttpRequest(), progress = form.querySelector('.upload-progress'), bar = progress.querySelector('span'), label = progress.querySelector('strong');
    xhr.open('POST', '/api/evidence');
    const token = localStorage.getItem('forensicToken');
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.upload.onprogress = event => { if (!event.lengthComputable) return; const percent = Math.round(event.loaded / event.total * 100); bar.style.width = `${percent}%`; label.textContent = `${percent}%`; };
    xhr.onload = async () => { if (xhr.status < 200 || xhr.status >= 300) { let message = 'Không thể tải lên'; try { message = JSON.parse(xhr.responseText).detail || message; } catch {} return notify(message, true); } document.querySelector('#actionModal')?.remove(); await refreshData(); notify('Đã ghi nhận chứng cứ bằng giao dịch Fabric hợp lệ'); };
    xhr.onerror = () => notify('Kết nối tải lên bị gián đoạn.', true);
    progress.classList.add('active');
    xhr.send(new FormData(form));
  };
}
function openResourceForm(type) { const config = type === 'project' ? ['Tạo dự án mới','/api/projects',{name:'Tên dự án',description:'Mô tả',status:'Trạng thái'}] : type === 'investigator' ? ['Thêm nhân viên và tài khoản','/api/investigators',{name:'Họ tên',email:'Email',role:'Vai trò',enrollmentID:'Enrollment ID Fabric',organization:'Tổ chức Fabric',username:'Tên đăng nhập',password:'Mật khẩu'}] : ['Tạo báo cáo','/api/reports',{name:'Tên báo cáo',project_id:'Mã dự án',description:'Mô tả'}]; const roleOptions = [['INVESTIGATOR','Điều tra viên'],['ANALYST','Chuyên viên phân tích'],['SUPERVISOR','Người giám sát'],['OBSERVER','Quan sát viên']]; if (type === 'report' && !projects.length) return notify('Cần có ít nhất một dự án trước khi tạo báo cáo.', true); const fields = Object.entries(config[2]).map(([name,label]) => { if (name === 'role' && type === 'investigator') return `<label>${label}<select name="role" required>${roleOptions.map(([value,text]) => `<option value="${value}">${text}</option>`).join('')}</select></label>`; if (name === 'organization' && type === 'investigator') return `<label>${label}<input name="organization" value="Org1MSP" readonly required></label>`; if (name === 'project_id' && type === 'report') return `<label>${label}<select name="project_id" required><option value="">Chọn dự án</option>${projects.map(project => `<option value="${escapeHtml(project.projectID)}">${escapeHtml(project.projectID)} - ${escapeHtml(project.name)}</option>`).join('')}</select></label>`; return `<label>${label}<input name="${name}" ${name === 'password' ? 'type="password" minlength="12" autocomplete="new-password"' : ''} required></label>`; }).join(''); const isReport = type === 'report'; openModal(config[0], `${isReport ? '<p class="small-note">Chọn dự án để lập báo cáo và tổng hợp bằng chứng liên quan.</p>' : type === 'investigator' ? '<p class="small-note">Identity sẽ được cấp trên Fabric CA của Org1MSP. Enrollment ID phải là duy nhất.</p>' : ''}<form id="resourceForm" class="action-form">${fields}<button type="submit" class="btn primary">${isReport ? 'Lưu báo cáo' : type === 'investigator' ? 'Lưu nhân viên và tài khoản' : 'Lưu dự án'}</button></form>`); const form = document.querySelector('#actionModal #resourceForm'); form.onsubmit = async event => { event.preventDefault(); const response = await fetch(config[1], { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.fromEntries(new FormData(form))) }); if (!response.ok) return notify(await responseError(response, isReport ? 'Không thể tạo báo cáo.' : 'Không thể tạo dữ liệu.'), true); document.querySelector('#actionModal')?.remove(); await refreshData(); notify(isReport ? 'Đã tạo báo cáo thành công.' : type === 'investigator' ? 'Đã thêm nhân viên và tài khoản thành công.' : 'Đã tạo dự án thành công.'); }; }
function openRelationForm() { if (evidence.length < 2) return notify('Cần có ít nhất hai chứng cứ để tạo quan hệ.', true); const options = evidence.map(item => `<option value="${escapeHtml(item.evidenceID)}">${escapeHtml(item.evidenceID)} - ${escapeHtml(item.fileName || 'Chứng cứ')}</option>`).join(''); const types = ['PARENT_CHILD','FILE_EMAIL','FILE_DEVICE','FILE_IP','DISCOVERED_FROM','RELATED'].map(type => `<option value="${type}">${type}</option>`).join(''); openModal('Thêm quan hệ chứng cứ', `<form id="relationForm" class="action-form"><label>Chứng cứ nguồn<select name="from_evidence" required>${options}</select></label><label>Chứng cứ đích<select name="to_evidence" required>${options}</select></label><label>Loại quan hệ<select name="relation_type" required>${types}</select></label><label>Mô tả quan hệ<input name="relation" maxlength="100" placeholder="Ví dụ: phát hiện trong email..." required></label><label>Nguồn gốc/phát hiện<textarea name="discovery_note" maxlength="500" placeholder="Mô tả nguồn và quá trình phát hiện"></textarea></label><button type="submit" class="btn primary">Lưu quan hệ</button></form>`); const form = document.querySelector('#actionModal #relationForm'); form.addEventListener('submit', async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(form)); if (payload.from_evidence === payload.to_evidence) return notify('Chọn hai chứng cứ khác nhau.', true); const response = await fetch('/api/relations', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) }); if (!response.ok) return notify(await responseError(response, 'Không thể tạo quan hệ.'), true); document.querySelector('#actionModal')?.remove(); await refreshData(); notify('Đã tạo quan hệ chứng cứ thành công.'); }); }
function openRelationEdit(relation) { if (!relation) return; const options = evidence.map(item => `<option value="${escapeHtml(item.evidenceID)}" ${item.evidenceID === relation.from_evidence ? 'selected' : ''}>${escapeHtml(item.evidenceID)} - ${escapeHtml(item.fileName || 'Chứng cứ')}</option>`).join(''); const targets = evidence.map(item => `<option value="${escapeHtml(item.evidenceID)}" ${item.evidenceID === relation.to_evidence ? 'selected' : ''}>${escapeHtml(item.evidenceID)} - ${escapeHtml(item.fileName || 'Chứng cứ')}</option>`).join(''); const types = ['PARENT_CHILD','FILE_EMAIL','FILE_DEVICE','FILE_IP','DISCOVERED_FROM','RELATED'].map(type => `<option value="${type}" ${type === (relation.relation_type || 'RELATED') ? 'selected' : ''}>${type}</option>`).join(''); openModal('Sửa quan hệ chứng cứ', `<form id="relationEditForm" class="action-form"><label>Chứng cứ nguồn<select name="from_evidence" required>${options}</select></label><label>Chứng cứ đích<select name="to_evidence" required>${targets}</select></label><label>Loại quan hệ<select name="relation_type" required>${types}</select></label><label>Mô tả quan hệ<input name="relation" maxlength="100" value="${escapeHtml(relation.relation)}" required></label><label>Nguồn gốc/phát hiện<textarea name="discovery_note" maxlength="500">${escapeHtml(relation.discovery_note || '')}</textarea></label><button class="btn primary">Lưu thay đổi</button></form>`); document.querySelector('#relationEditForm').onsubmit = async event => { event.preventDefault(); const payload = Object.fromEntries(new FormData(event.target)); if (payload.from_evidence === payload.to_evidence) return notify('Chọn hai chứng cứ khác nhau.', true); const response = await fetch(`/api/relations/${encodeURIComponent(relation.relationID)}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) }); if (!response.ok) return notify(await responseError(response, 'Không thể sửa quan hệ.'), true); document.querySelector('#actionModal').remove(); await refreshData(); notify('Đã cập nhật quan hệ chứng cứ thành công.'); }; }
async function deleteRelation(relation) { if (!relation || !await confirmAction(`Xóa quan hệ ${relation.relationID}?`)) return; const response = await fetch(`/api/relations/${encodeURIComponent(relation.relationID)}`, { method:'DELETE' }); if (!response.ok) return notify(await responseError(response, 'Không thể xóa quan hệ.'), true); await refreshData(); notify('Đã xóa quan hệ chứng cứ thành công.'); }
function custodyPeopleOptions(includeCurrent = false) { const people = investigators.filter(person => (person.accountStatus || person.status) === 'ACTIVE' && (person.fabricIdentityStatus || person.status) === 'ACTIVE').map(person => ({ value: person.investigatorID, label: `${person.name} (${person.investigatorID})` })); const current = selected?.currentHolder || selected?.investigator; if (includeCurrent && current && !people.some(person => person.value === current)) people.unshift({ value: current, label: current }); return people.length ? people.map(person => `<option value="${escapeHtml(person.value)}">${escapeHtml(person.label)}</option>`).join('') : '<option value="">Chưa có nhân viên</option>'; }
function openCustody(type) {
  if (!selected) return notify('Hãy chọn một chứng cứ trước.', true);
  const options = custodyPeopleOptions();
  const fields = type === 'access'
    ? `<label>Evidence ID<input value="${escapeHtml(selected.evidenceID)}" readonly></label><label>Actor ID<select name="actor_id" required>${options}</select></label><label>Lý do truy cập<textarea name="reason" required></textarea></label>`
    : `<label>Evidence ID<input value="${escapeHtml(selected.evidenceID)}" readonly></label><label>From holder<select name="from_holder" required>${custodyPeopleOptions(true)}</select></label><label>To holder<select name="to_holder" required>${custodyPeopleOptions()}</select></label><label>Actor ID<select name="actor_id" required>${options}</select></label><label>Lý do bàn giao<textarea name="reason" required></textarea></label>`;
  openModal(type === 'access' ? 'Ghi nhận truy cập chứng cứ' : 'Chuyển giao chứng cứ', `<form id="custodyForm" class="action-form">${fields}<button type="submit" class="btn primary">Ghi nhận giao dịch Fabric</button></form>`);
  const form = document.querySelector('#actionModal #custodyForm');
  form.onsubmit = async event => {
    event.preventDefault();
    const response = await fetch(`/api/evidence/${encodeURIComponent(selected.evidenceID)}/${type}`, { method:'POST', body:new FormData(form) });
    if (!response.ok) return notify(await responseError(response, 'Không thể ghi nhận thao tác.'), true);
    const receipt = await response.json();
    document.querySelector('#actionModal')?.remove();
    await refreshData();
    if (type === 'transfer') {
      notify(`Đã chuyển giao chứng cứ thành công. Mã giao dịch: ${(receipt.txID || '').slice(0, 14)}`);
    } else if (type === 'access') {
      notify(`Đã ghi nhận truy cập chứng cứ thành công. Mã giao dịch: ${(receipt.txID || '').slice(0, 14)}`);
    }
  };
}
function openReceive() {
  if (!selected) return;
  openModal('Tiếp nhận chứng cứ', `<form id="receiveForm" class="action-form"><label>Người bàn giao<input name="from_holder" value="${escapeHtml(selected.currentHolder || selected.investigator || '')}" required></label><label>Người tiếp nhận<select name="actor_id" required>${custodyPeopleOptions()}</select></label><label>Lý do tiếp nhận<textarea name="reason" required></textarea></label><button class="btn primary">Ghi nhận RECEIVE</button></form>`);
  document.querySelector('#receiveForm').onsubmit = async event => {
    event.preventDefault();
    const response = await fetch(`/api/evidence/${encodeURIComponent(selected.evidenceID)}/receive`, { method:'POST', body:new FormData(event.target) });
    if (!response.ok) return notify(await responseError(response, 'Không thể ghi nhận tiếp nhận.'), true);
    const receipt = await response.json();
    document.querySelector('#actionModal')?.remove();
    await refreshData();
    notify(`Đã tiếp nhận chứng cứ thành công. Mã giao dịch: ${(receipt.txID || '').slice(0, 14)}`);
  };
}
function openAnalyze() {
  if (!selected) return;
  openModal('Ghi nhận phân tích', `<form id="analyzeForm" class="action-form"><label>Người phân tích<select name="actor_id" required>${custodyPeopleOptions()}</select></label><label>Mục đích/lý do<textarea name="reason" required></textarea></label><label>Kết quả phân tích<textarea name="result" required></textarea></label><button class="btn primary">Ghi nhận ANALYZE</button></form>`);
  document.querySelector('#analyzeForm').onsubmit = async event => {
    event.preventDefault();
    const response = await fetch(`/api/evidence/${encodeURIComponent(selected.evidenceID)}/analyze`, { method:'POST', body:new FormData(event.target) });
    if (!response.ok) return notify(await responseError(response, 'Không thể ghi nhận phân tích.'), true);
    const receipt = await response.json();
    document.querySelector('#actionModal')?.remove();
    await refreshData();
    notify(`Đã ghi nhận phân tích thành công. Mã giao dịch: ${(receipt.txID || '').slice(0, 14)}`);
  };
}
function openCaseMemberForm() { const investigatorsOptions = investigators.map(person => `<option value="${escapeHtml(person.investigatorID)}">${escapeHtml(person.investigatorID)} - ${escapeHtml(person.name)}</option>`).join(''); const projectOptions = projects.map(project => `<option value="${escapeHtml(project.projectID)}">${escapeHtml(project.projectID)} - ${escapeHtml(project.name)}</option>`).join(''); if (!investigatorsOptions || !projectOptions) return notify('Cần có dự án và người tham gia trước.', true); const roles = ['INVESTIGATOR','ANALYST','SUPERVISOR','OBSERVER'].map(role => `<option value="${role}">${role}</option>`).join(''); openModal('Phân công thành viên dự án', `<form id="memberForm" class="action-form"><label>Mã dự án<select name="case_id" required>${projectOptions}</select></label><label>Thành viên<select name="investigator_id" required>${investigatorsOptions}</select></label><label>Vai trò<select name="role" required>${roles}</select></label><button class="btn primary">Lưu phân công</button></form>`); document.querySelector('#memberForm').onsubmit = async event => { event.preventDefault(); const form = new FormData(event.target); const caseId = form.get('case_id'); const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}/members`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ investigator_id: form.get('investigator_id'), role: form.get('role') }) }); if (!response.ok) return notify(await responseError(response, 'Không thể phân công thành viên.'), true); document.querySelector('#actionModal').remove(); notify('Đã phân công thành viên dự án'); }; }
async function verifySelected() { if (!selected) return notify('Hãy chọn một chứng cứ trước.', true); const response = await fetch(`/api/evidence/${selected.evidenceID}/verify`, { method:'POST' }); if (!response.ok) return notify(await responseError(response, 'Không thể xác minh chứng cứ.'), true); const result = await response.json(); notify(result.status === 'MATCH' ? 'Đã xác minh chứng cứ: hàm băm SHA-256 và Merkle Root khớp.' : result.status === 'MISMATCH' ? 'Phát hiện sai lệch: chứng cứ đã thay đổi.' : 'Chưa thể xác minh chứng cứ.', result.status !== 'MATCH'); await refreshData(); }
async function refreshData() { const responses = await Promise.all(['/api/evidence','/api/projects','/api/investigators','/api/reports','/api/relations','/api/ledger'].map(url => fetch(url))); const failed = responses.find(response => response.status === 401); if (failed) { localStorage.removeItem('forensicToken'); localStorage.removeItem('forensicUser'); authUser = null; return showAuth(); } if (responses.some(response => !response.ok)) throw new Error('Unable to load protected dashboard data'); const [loadedEvidence, loadedProjects, loadedPeople, loadedReports, loadedRelations, loadedLedger] = await Promise.all(responses.map(response => response.json())); evidence = loadedEvidence; projects = loadedProjects; investigators = loadedPeople; reports = loadedReports; relations = loadedRelations; ledger = loadedLedger; if (selectedRelationId && !relations.some(item => item.relationID === selectedRelationId)) selectedRelationId = null; selected = evidence.find(item => item.evidenceID === selected?.evidenceID) || evidence[0] || null; mount(currentView); if (currentView === 'graph') renderGraph(); }
async function downloadSelected() { if (!selected) return; const response = await fetch(`/api/evidence/${selected.evidenceID}/file`); if (!response.ok) return notify(await responseError(response, 'Không thể tải file.'), true); const blob = await response.blob(); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = selected.fileName || selected.evidenceID; link.click(); URL.revokeObjectURL(link.href); }
function bindActions() { app.querySelectorAll('.btn').forEach(button => { if (button.dataset.bound || ['addRelation', 'editRelation', 'deleteRelation', 'transferDownload', 'transferVerify', 'transferAccess', 'transferReceive', 'transferAnalyze', 'transferOpenForm'].includes(button.id) || button.classList.contains('report-pdf')) return; button.dataset.bound = '1'; button.onclick = () => { const action = button.textContent.trim(); if (action.includes('Thêm chứng cứ')) openUpload(); else if (action.includes('Thêm quan hệ')) openRelationForm(); else if (action.includes('Tạo dự án')) openResourceForm('project'); else if (action.includes('Phân công thành viên')) openCaseMemberForm(); else if (action.includes('Thêm điều tra viên') || action.includes('Thêm nhân viên')) openResourceForm('investigator'); else if (action === '+ Tạo mới') openResourceForm('report'); else if (action === 'ACCESS') openCustody('access'); else if (action === 'TRANSFER') openCustody('transfer'); else if (action.includes('Verify')) verifySelected(); else if (action.includes('Tải file') && selected) downloadSelected(); else refreshData(); }; }); app.querySelectorAll('.ledger-verify').forEach(button => button.onclick = () => verifyLedgerTransaction(button.dataset.txId)); app.querySelectorAll('.report-detail').forEach(button => button.onclick = () => openReportDetail(button.dataset.reportId)); app.querySelectorAll('.report-pdf').forEach(button => button.onclick = async () => { const response = await fetch(`/api/reports/${encodeURIComponent(button.dataset.reportId)}/pdf`); if (!response.ok) return notify(await responseError(response, 'Không thể xuất PDF.'), true); const blob = await response.blob(); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `${button.dataset.reportId}.pdf`; link.click(); URL.revokeObjectURL(link.href); }); }
async function init() { try { const health = await fetch('/api/health').then(response => response.json()); document.querySelector('#sideConnection').textContent = health.status !== 'connected' ? 'Trạng thái: Không kết nối' : health.ledger === 'fabric-peer' ? 'Trạng thái: Đã kết nối Blockchain' : 'Trạng thái: Local adapter'; if (!localStorage.getItem('forensicToken')) return showAuth(); const meResponse = await fetch('/api/auth/me'); if (!meResponse.ok) { localStorage.removeItem('forensicToken'); localStorage.removeItem('forensicUser'); authUser = null; return showAuth(); } authUser = await meResponse.json(); localStorage.setItem('forensicUser', JSON.stringify(authUser)); updateUserHeader(); await refreshData(); if (authUser.mustChangePassword) openPasswordChange(true); } catch { document.querySelector('#sideConnection').textContent = 'Trạng thái: Không kết nối'; if (authUser) mount(); else showAuth(); } }
nav.forEach(item => item.addEventListener('click', () => mount(item.dataset.view)));
init();

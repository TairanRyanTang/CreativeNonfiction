import streamlit as st
import pandas as pd
import os
import json
import hashlib
import zipfile
import io
from datetime import datetime

# ---------- 安全配置 ----------
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {'doc', 'docx'}

UPLOAD_DIR = 'uploads'
DATA_FILE = 'data.json'
VIRUS_SCAN_DIR = 'virus_quarantine'
ADMIN_PASSWORD_HASH = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'  # 默认密码 "password"

GRADE_LIST = [
    'Grade 2027',
    'Grade 2028',
    'Grade 2029'
]

# 创建目录
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(VIRUS_SCAN_DIR, exist_ok=True)

# ---------- 病毒检测函数 ----------
def scan_word_document(file_content, filename):
    errors = []
    if filename.lower().endswith('.docx'):
        if file_content[:4] != b'PK\x03\x04':
            errors.append("无效的docx文件格式")
    elif filename.lower().endswith('.doc'):
        ole_header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
        if len(file_content) < 8 or file_content[:8] != ole_header:
            errors.append("无效的doc文件格式")
    else:
        errors.append("不支持的文件格式，请上传 .doc 或 .docx")
        return errors

    if filename.lower().endswith('.docx'):
        try:
            with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
                for name in zf.namelist():
                    macro_patterns = [
                        'vba', 'macro', 'vbaproject',
                        '_rels/vba', 'word/vba', 'bin/',
                        'vbaData.xml', 'vbaProject.bin'
                    ]
                    name_lower = name.lower()
                    if any(pattern in name_lower for pattern in macro_patterns):
                        errors.append(f"检测到宏文件：{name}")
                        break
        except zipfile.BadZipFile:
            errors.append("docx文件损坏或格式异常")
        except Exception as e:
            errors.append(f"文件解析异常：{str(e)[:50]}")

    ole_signatures = [
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
        b'ObjectPool', b'Embedded', b'objclass',
    ]
    for sig in ole_signatures:
        if sig in file_content:
            errors.append("检测到嵌入对象（OLE），可能存在风险")
            break

    if len(file_content) < 1024:
        errors.append("文件过小，可能为空文档或损坏")
    if len(file_content) > 50 * 1024 * 1024:
        errors.append("文件过大，超过50MB限制")

    executable_patterns = [
        b'CreateObject', b'WScript.Shell', b'Shell.Application',
        b'Run(', b'Exec(', b'System.', b'Process.Start',
        b'<script', b'javascript:', b'vbscript:',
        b'eval(', b'execute(', b'ActiveXObject',
        b'GetObject(', b'CreateObject(',
        b'MSXML2.XMLHTTP', b'WinHttp.WinHttpRequest',
    ]
    content_lower = file_content.lower()
    for pattern in executable_patterns:
        if pattern.lower() in content_lower:
            errors.append(f"检测到可疑代码特征：{pattern.decode('utf-8', errors='ignore')}")
            break

    dangerous_headers = [b'MZ', b'%PDF']
    header_check = file_content[:100]
    for header in dangerous_headers:
        if header in header_check:
            if filename.lower().endswith('.docx') and header == b'PK\x03\x04':
                continue
            errors.append("检测到异常文件特征，可能为伪装文件")
            break
    return errors

def safe_filename(original_name, user_id):
    ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"不支持的文件类型：{ext}")
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
    return f"{user_id}_{timestamp}.{ext}"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_admin(password):
    return hash_password(password) == ADMIN_PASSWORD_HASH

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            backup_file = f"data_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            os.rename(DATA_FILE, backup_file)
            return {'submissions': [], 'users': {}}
    return {'submissions': [], 'users': {}}

def save_data(data):
    temp_file = DATA_FILE + '.tmp'
    with open(temp_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(temp_file, DATA_FILE)

def log_activity(action, user_id, detail=""):
    log_entry = {
        'time': datetime.now().isoformat(),
        'action': action,
        'user': user_id,
        'detail': detail
    }
    with open('security.log', 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')

def get_user_key(grade, student_name):
    return f"{grade}_{student_name}".strip()

# ---------- 页面配置 ----------
st.set_page_config(page_title="比赛作品提交系统", page_icon="🔒")
st.title("📝 比赛作品提交系统")

# ---------- 管理员登录 ----------
with st.expander("🔐 管理员登录"):
    admin_pass = st.text_input("管理员密码", type="password", key="admin_pass_main")
    if st.button("验证身份", key="admin_login_main"):
        if verify_admin(admin_pass):
            st.session_state.is_admin = True
            log_activity('admin_login', 'admin', 'success')
            st.success("✅ 验证通过")
            st.rerun()
        else:
            st.error("❌ 密码错误")
            log_activity('admin_login', 'admin', 'failed')

# ---------- 会话初始化 ----------
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False

# ---------- 用户登录/注册 ----------
if st.session_state.user_id is None:
    st.subheader("👤 登录 / 注册")
    st.caption("请选择你的年级并输入姓名，系统将自动识别你是新用户还是老用户")
    col1, col2 = st.columns(2)
    with col1:
        selected_grade = st.selectbox("选择年级", GRADE_LIST)
    with col2:
        student_name = st.text_input("真实姓名", max_chars=20, placeholder="张三")
    use_custom_grade = st.checkbox("如果上面没有你的年级，点这里输入")
    if use_custom_grade:
        selected_grade = st.text_input("手动输入年级", placeholder="例如：Grade 2027")
    agree = st.checkbox("我承诺提交的作品为本人原创")
    if st.button("登录 / 注册", type="primary"):
        errors = []
        if not selected_grade:
            errors.append("请选择或输入年级")
        if not student_name:
            errors.append("请输入姓名")
        if not agree:
            errors.append("请勾选原创承诺")
        if errors:
            for err in errors:
                st.error(f"❌ {err}")
        else:
            user_key = get_user_key(selected_grade, student_name)
            st.session_state.user_id = user_key
            st.session_state.user_grade = selected_grade
            st.session_state.user_name = student_name
            log_activity('login_success', user_key)
            st.success(f"✅ 欢迎，{selected_grade} {student_name}！")
            st.rerun()
    st.stop()

# ---------- 已登录状态 ----------
st.success(f"✅ 当前用户：{st.session_state.user_grade} {st.session_state.user_name}")

# ---------- 检查旧作品 ----------
data = load_data()
user_key = st.session_state.user_id
user_submission = None
for s in data['submissions']:
    if s['user_key'] == user_key:
        user_submission = s
        break

if user_submission:
    st.warning("⚠️ 你已有作品，再次提交将覆盖之前的作品。")
    with st.expander("📄 查看当前提交记录"):
        st.write(f"**年级**：{user_submission['class_name']}")
        st.write(f"**姓名**：{user_submission['student_name']}")
        st.write(f"**作品名称**：{user_submission['work_title']}")
        st.write(f"**作品简介**：{user_submission['work_desc']}")
        st.write(f"**提交时间**：{user_submission['time']}")
        if user_submission.get('file_path') and os.path.exists(user_submission['file_path']):
            file_size = os.path.getsize(user_submission['file_path']) / 1024 / 1024
            st.write(f"**附件**：{os.path.basename(user_submission['file_path'])} ({file_size:.2f} MB)")

# ---------- 提交表单 ----------
st.subheader("📤 提交你的Word文档作品")
st.caption("⚠️ 仅接受 .doc 或 .docx 格式，文件大小不超过20MB")

with st.form("submit_form"):
    st.text_input("年级", value=st.session_state.user_grade, disabled=True)
    st.text_input("姓名", value=st.session_state.user_name, disabled=True)
    work_title = st.text_input("作品名称", max_chars=100, placeholder="《我的参赛作品》")
    work_desc = st.text_area("作品简介", max_chars=500, placeholder="请简要描述你的作品内容...")
    uploaded_file = st.file_uploader(
        "📎 上传Word文档（仅支持 .doc / .docx）",
        type=['doc', 'docx'],
        accept_multiple_files=False
    )
    if uploaded_file is not None:
        file_size = uploaded_file.size
        if file_size > MAX_FILE_SIZE:
            st.error(f"❌ 文件大小 {file_size/1024/1024:.1f}MB 超过限制")
        else:
            st.success(f"✅ 已选择文件：{uploaded_file.name} ({file_size/1024:.1f}KB)")
    submitted = st.form_submit_button("提交作品", type="primary")

if submitted:
    errors = []
    if not work_title:
        errors.append("作品名称不能为空")
    if uploaded_file is None:
        errors.append("请上传Word文档")
    elif uploaded_file.size > MAX_FILE_SIZE:
        errors.append("文件大小超过限制")
    else:
        file_content = uploaded_file.read()
        scan_errors = scan_word_document(file_content, uploaded_file.name)
        if scan_errors:
            errors.append(f"⚠️ 安全检测未通过：{', '.join(scan_errors)}")
            quarantine_name = f"{user_key}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uploaded_file.name}"
            quarantine_path = os.path.join(VIRUS_SCAN_DIR, quarantine_name)
            with open(quarantine_path, 'wb') as f:
                f.write(file_content)
            log_activity('virus_blocked', user_key, f"{uploaded_file.name} - {', '.join(scan_errors)}")
    if errors:
        for err in errors:
            if "安全检测" in err:
                st.error(f"⛔ {err}")
                st.warning("你的文件已被隔离，如有疑问请联系管理员")
            else:
                st.error(f"❌ {err}")
    else:
        try:
            data = load_data()
            for idx, s in enumerate(data['submissions']):
                if s['user_key'] == user_key:
                    old_file = s.get('file_path')
                    if old_file and os.path.exists(old_file):
                        os.remove(old_file)
                        log_activity('file_removed', user_key, f"Deleted old file: {old_file}")
                    data['submissions'].pop(idx)
                    break
            safe_name = safe_filename(uploaded_file.name, user_key)
            file_path = os.path.join(UPLOAD_DIR, safe_name)
            with open(file_path, 'wb') as f:
                f.write(file_content)
            data['submissions'].append({
                'user_key': user_key,
                'class_name': st.session_state.user_grade,
                'student_name': st.session_state.user_name,
                'work_title': work_title,
                'work_desc': work_desc,
                'file_path': file_path,
                'file_size': uploaded_file.size,
                'file_type': uploaded_file.type,
                'time': datetime.now().isoformat()
            })
            save_data(data)
            log_activity('submit_success', user_key, work_title)
            st.success("🎉 作品提交成功！" + (" (已覆盖旧作品)" if user_submission else ""))
            st.balloons()
            st.rerun()
        except Exception as e:
            log_activity('submit_error', user_key, str(e))
            st.error(f"提交异常，请稍后重试")

# ---------- 管理员仪表板 ----------
if st.session_state.get('is_admin', False):
    st.sidebar.title("📊 管理仪表板")
    st.sidebar.metric("总参赛人数", len(data['submissions']))
    virus_count = len(os.listdir(VIRUS_SCAN_DIR)) if os.path.exists(VIRUS_SCAN_DIR) else 0
    st.sidebar.metric("隔离文件数", virus_count)

    if data['submissions']:
        df = pd.DataFrame(data['submissions'])
        st.sidebar.dataframe(df[['class_name', 'student_name', 'work_title', 'time']])
        for idx, row in df.iterrows():
            if row['file_path'] and os.path.exists(row['file_path']):
                with open(row['file_path'], 'rb') as f:
                    st.sidebar.download_button(
                        label=f"📥 {row['student_name']} - {row['work_title']}",
                        data=f,
                        file_name=os.path.basename(row['file_path']),
                        key=f"download_{idx}"
                    )
        if st.sidebar.button("📤 导出所有数据（JSON）"):
            json_str = json.dumps(data['submissions'], ensure_ascii=False, indent=2)
            st.sidebar.download_button(
                label="下载JSON文件",
                data=json_str,
                file_name=f"参赛数据_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json"
            )

    # 安全日志查看
    with st.sidebar.expander("📋 安全日志"):
        if os.path.exists('security.log'):
            try:
                with open('security.log', 'r', encoding='utf-8') as log_file:
                    logs = log_file.readlines()
                    if logs:
                        recent_logs = logs[-50:]
                        for line in reversed(recent_logs):
                            try:
                                entry = json.loads(line)
                                st.text(f"{entry['time']} - {entry['action']} - {entry['user']} - {entry['detail']}")
                            except:
                                st.text(line.strip())
                    else:
                        st.success("✅ 暂无日志")
            except Exception as e:
                st.error(f"读取日志失败: {e}")
        else:
            st.info("日志文件尚未生成")

    # 隔离文件列表
    with st.sidebar.expander("⚠️ 隔离文件列表"):
        if os.path.exists(VIRUS_SCAN_DIR):
            virus_files = os.listdir(VIRUS_SCAN_DIR)
            if virus_files:
                for vf in virus_files:
                    st.sidebar.text(f"🔴 {vf}")
            else:
                st.sidebar.success("✅ 无隔离文件")

    # 一键删除所有作品
    st.sidebar.divider()
    st.sidebar.error("🧹 危险操作区")
    confirm_delete = st.sidebar.checkbox("⚠️ 我确认要删除所有作品及文件，此操作不可恢复")
    if st.sidebar.button("一键删除所有作品", disabled=not confirm_delete):
        if confirm_delete:
            if os.path.exists(UPLOAD_DIR):
                for file in os.listdir(UPLOAD_DIR):
                    file_path = os.path.join(UPLOAD_DIR, file)
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        st.sidebar.error(f"删除文件失败：{file} - {e}")
            data['submissions'] = []
            save_data(data)
            log_activity('admin_delete_all', 'admin', 'All submissions and files deleted')
            st.sidebar.success("✅ 所有作品及文件已删除")
            st.rerun()

    if st.sidebar.button("🚪 退出管理"):
        st.session_state.is_admin = False
        st.rerun()

# ---------- 安全特性说明 ----------
st.sidebar.divider()
st.sidebar.caption("🔒 安全特性：")
st.sidebar.caption("- 仅接受Word文档 (.doc/.docx)")
st.sidebar.caption("- 宏病毒自动扫描")
st.sidebar.caption("- 恶意代码特征检测")
st.sidebar.caption("- 危险文件自动隔离")
st.sidebar.caption("- 文件大小限制 (20MB)")
st.sidebar.caption("- 提交可覆盖，以最新为准")

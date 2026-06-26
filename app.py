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
ADMIN_PASSWORD_HASH = '78d34f89d28f7278476ddb7e382f37535e2eca35a5b0ffc7c84df20f7dcdd789'

GRADE_LIST = [
    'Grade 2027',
    'Grade 2028',
    'Grade 2029'
]

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(VIRUS_SCAN_DIR, exist_ok=True)

# ---------- 病毒检测 ----------
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
                    if any(p in name.lower() for p in macro_patterns):
                        errors.append(f"检测到宏文件：{name}")
                        break
        except zipfile.BadZipFile:
            errors.append("docx文件损坏或格式异常")
        except Exception as e:
            errors.append(f"文件解析异常：{str(e)[:50]}")

    for sig in [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', b'ObjectPool', b'Embedded', b'objclass']:
        if sig in file_content:
            errors.append("检测到嵌入对象（OLE），可能存在风险")
            break

    if len(file_content) < 1024:
        errors.append("文件过小，可能为空或损坏")
    if len(file_content) > 50 * 1024 * 1024:
        errors.append("文件过大")

    for p in [b'CreateObject', b'WScript.Shell', b'Run(', b'<script', b'eval(']:
        if p.lower() in file_content.lower():
            errors.append(f"检测到可疑代码特征")
            break
    return errors

def safe_filename(original_name, user_id):
    ext = original_name.rsplit('.', 1)[-1].lower()
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
            backup = f"data_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            os.rename(DATA_FILE, backup)
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

# ---------- 会话初始化 ----------
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False

# ---------- 管理员登录（首页顶部，仅未登录管理时显示） ----------
if not st.session_state.is_admin:
    with st.expander("🔐 管理员登录"):
        admin_pass = st.text_input("管理员密码", type="password", key="admin_pass_main")
        if st.button("验证身份", key="admin_login_main"):
            if verify_admin(admin_pass):
                st.session_state.is_admin = True
                log_activity('admin_login', 'admin', 'success')
                st.success("✅ 验证通过，管理面板已激活")
                st.rerun()
            else:
                st.error("❌ 密码错误")
                log_activity('admin_login', 'admin', 'failed')

# ---------- 如果是管理员，显示管理界面并停止 ----------
if st.session_state.is_admin:
    st.success("🔓 管理员模式")
    st.header("📊 管理仪表板")
    data = load_data()
    col1, col2 = st.columns(2)
    with col1:
        st.metric("总参赛人数", len(data['submissions']))
    with col2:
        virus_count = len(os.listdir(VIRUS_SCAN_DIR)) if os.path.exists(VIRUS_SCAN_DIR) else 0
        st.metric("隔离文件数", virus_count)

    if data['submissions']:
        df = pd.DataFrame(data['submissions'])
        st.subheader("提交列表")
        st.dataframe(df[['class_name', 'student_name', 'work_title', 'time']])
        for idx, row in df.iterrows():
            if row['file_path'] and os.path.exists(row['file_path']):
                with open(row['file_path'], 'rb') as f:
                    st.download_button(
                        label=f"📥 下载 {row['student_name']} 的作品",
                        data=f,
                        file_name=os.path.basename(row['file_path']),
                        key=f"download_{idx}"
                    )
        json_str = json.dumps(data['submissions'], ensure_ascii=False, indent=2)
        st.download_button(
            label="📤 导出所有数据（JSON）",
            data=json_str,
            file_name=f"参赛数据_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json"
        )
    else:
        st.info("暂无提交")

    # 安全日志
    with st.expander("📋 安全日志（最近50条）"):
        if os.path.exists('security.log'):
            try:
                with open('security.log', 'r', encoding='utf-8') as log_file:
                    logs = log_file.readlines()
                    if logs:
                        for line in reversed(logs[-50:]):
                            try:
                                entry = json.loads(line)
                                st.text(f"{entry['time']} - {entry['action']} - {entry['user']} - {entry['detail']}")
                            except:
                                st.text(line.strip())
                    else:
                        st.success("暂无日志")
            except Exception as e:
                st.error(f"读取日志失败: {e}")
        else:
            st.info("日志文件尚未生成")

    # 隔离文件
    with st.expander("⚠️ 隔离文件列表"):
        if os.path.exists(VIRUS_SCAN_DIR):
            virus_files = os.listdir(VIRUS_SCAN_DIR)
            if virus_files:
                for vf in virus_files:
                    st.text(f"🔴 {vf}")
            else:
                st.success("✅ 无隔离文件")

    # 危险操作
    st.divider()
    st.error("🧹 危险操作区")
    confirm_delete = st.checkbox("⚠️ 我确认要删除所有作品及文件，此操作不可恢复", key="confirm_delete")
    if st.button("一键删除所有作品", disabled=not confirm_delete):
        if confirm_delete:
            if os.path.exists(UPLOAD_DIR):
                for file in os.listdir(UPLOAD_DIR):
                    file_path = os.path.join(UPLOAD_DIR, file)
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        st.error(f"删除文件失败：{file} - {e}")
            data['submissions'] = []
            save_data(data)
            log_activity('admin_delete_all', 'admin', 'All deleted')
            st.success("✅ 所有作品及文件已删除")
            st.rerun()

    if st.button("🚪 退出管理"):
        st.session_state.is_admin = False
        st.rerun()
    st.stop()

# ---------- 普通用户登录/注册 ----------
if st.session_state.user_id is None:
    st.subheader("👤 登录 / 注册")
    st.caption("请选择你的年级并输入姓名")
    col1, col2 = st.columns(2)
    with col1:
        selected_grade = st.selectbox("选择年级", GRADE_LIST)
    with col2:
        student_name = st.text_input("真实姓名", max_chars=20, placeholder="张三")
    use_custom = st.checkbox("如果上面没有你的年级，点这里输入")
    if use_custom:
        selected_grade = st.text_input("手动输入年级", placeholder="例如：Grade 2027")
    agree = st.checkbox("我承诺提交的作品为本人原创")
    if st.button("登录 / 注册", type="primary"):
        if not selected_grade or not student_name or not agree:
            st.error("请填写所有字段并勾选承诺")
        else:
            user_key = get_user_key(selected_grade, student_name)
            st.session_state.user_id = user_key
            st.session_state.user_grade = selected_grade
            st.session_state.user_name = student_name
            log_activity('login_success', user_key)
            st.success(f"✅ 欢迎，{selected_grade} {student_name}！")
            st.rerun()
    st.stop()

# ---------- 已登录用户 ----------
st.success(f"✅ 当前用户：{st.session_state.user_grade} {st.session_state.user_name}")

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
            sz = os.path.getsize(user_submission['file_path']) / 1024 / 1024
            st.write(f"**附件**：{os.path.basename(user_submission['file_path'])} ({sz:.2f} MB)")

st.subheader("📤 提交你的Word文档作品")
st.caption("⚠️ 仅接受 .doc 或 .docx 格式，文件大小不超过20MB")

with st.form("submit_form"):
    st.text_input("年级", value=st.session_state.user_grade, disabled=True)
    st.text_input("姓名", value=st.session_state.user_name, disabled=True)
    work_title = st.text_input("作品名称", max_chars=100, placeholder="《我的参赛作品》")
    work_desc = st.text_area("作品简介", max_chars=500, placeholder="请简要描述你的作品内容...")
    uploaded_file = st.file_uploader(
        "📎 上传Word文档", type=['doc', 'docx'], accept_multiple_files=False
    )
    if uploaded_file is not None:
        if uploaded_file.size > MAX_FILE_SIZE:
            st.error(f"❌ 文件超过 {MAX_FILE_SIZE//1024//1024}MB 限制")
        else:
            st.success(f"✅ 已选择：{uploaded_file.name} ({uploaded_file.size/1024:.1f}KB)")
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
            log_activity('virus_blocked', user_key, quarantine_name)
    if errors:
        for e in errors:
            st.error(e)
    else:
        try:
            data = load_data()
            for idx, s in enumerate(data['submissions']):
                if s['user_key'] == user_key:
                    old_file = s.get('file_path')
                    if old_file and os.path.exists(old_file):
                        os.remove(old_file)
                        log_activity('file_removed', user_key, f"Deleted old: {old_file}")
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
            st.success("🎉 作品提交成功！")
            st.balloons()
            st.rerun()
        except Exception as e:
            log_activity('submit_error', user_key, str(e))
            st.error("提交异常，请稍后重试")

# ---------- 安全说明（侧边栏） ----------
st.sidebar.divider()
st.sidebar.caption("🔒 安全特性：")
st.sidebar.caption("- 仅接受Word文档")
st.sidebar.caption("- 宏病毒自动扫描")
st.sidebar.caption("- 恶意代码检测")
st.sidebar.caption("- 危险文件隔离")
st.sidebar.caption("- 20MB大小限制")
st.sidebar.caption("- 可覆盖提交")

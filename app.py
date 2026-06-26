import streamlit as st
import pandas as pd
import os
import json
import hashlib
import re
import zipfile
import magic  # 需要安装：pip install python-magic-bin (Windows) 或 python-magic (Linux/Mac)
from datetime import datetime
from pathlib import Path

# ---------- 安全配置 ----------
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB（Word文档通常不会太大）

# 只允许Word文档
ALLOWED_EXTENSIONS = {'doc', 'docx'}
ALLOWED_MIME_TYPES = {
    'application/msword',  # .doc
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'  # .docx
}

UPLOAD_DIR = 'uploads'
DATA_FILE = 'data.json'
VIRUS_SCAN_DIR = 'virus_quarantine'  # 隔离区
ADMIN_PASSWORD_HASH = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'

# 班级列表
CLASS_LIST = [
    '高一(1)班', '高一(2)班', '高一(3)班', '高一(4)班',
    '高二(1)班', '高二(2)班', '高二(3)班', '高二(4)班',
    '高三(1)班', '高三(2)班', '高三(3)班', '高三(4)班'
]

# 创建目录
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(VIRUS_SCAN_DIR, exist_ok=True)

# ---------- 病毒检测函数 ----------
def detect_macro_virus(file_content):
    """
    检测Word文档中的宏病毒
    原理：检查docx文件中的vbaProject.bin或宏相关文件
    """
    try:
        # 检查是否为docx (zip格式)
        if file_content[:4] == b'PK\x03\x04':  # ZIP文件头
            import io
            with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
                for name in zf.namelist():
                    # 检测宏文件
                    if any(x in name.lower() for x in [
                        'vba', 'macro', 'vbaproject', 
                        '_rels/vba', 'word/vba'
                    ]):
                        return True, f"检测到宏文件：{name}"
        return False, None
    except Exception as e:
        # 如果解压失败，可能是损坏文件或病毒伪装
        return True, f"文件结构异常：{str(e)[:50]}"

def detect_embedded_objects(file_content):
    """
    检测嵌入的OLE对象（可能包含恶意代码）
    """
    # 检测OLE对象头
    ole_signatures = [
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',  # OLE Compound File
        b'ObjectPool',  # 对象池
        b'Embedded',    # 嵌入对象
    ]
    for sig in ole_signatures:
        if sig in file_content:
            return True, f"检测到嵌入对象（OLE）"
    return False, None

def scan_word_document(file_content, filename):
    """
    综合病毒扫描
    """
    errors = []
    
    # 1. 文件头校验（魔数检测）
    if filename.lower().endswith('.docx'):
        # docx应该是ZIP格式
        if file_content[:4] != b'PK\x03\x04':
            errors.append("无效的docx文件格式")
    elif filename.lower().endswith('.doc'):
        # doc应该是OLE格式
        ole_header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
        if file_content[:8] != ole_header:
            errors.append("无效的doc文件格式")
    
    # 2. 宏病毒检测
    has_macro, macro_detail = detect_macro_virus(file_content)
    if has_macro:
        errors.append(f"检测到宏病毒：{macro_detail}")
    
    # 3. 嵌入式对象检测
    has_ole, ole_detail = detect_embedded_objects(file_content)
    if has_ole:
        errors.append(f"检测到危险嵌入对象：{ole_detail}")
    
    # 4. 文件大小异常检测（过小可能是空的，过大可能有隐藏内容）
    if len(file_content) < 1024:  # 小于1KB
        errors.append("文件过小，可能为空文档或损坏")
    
    # 5. 检测可执行代码特征
    executable_patterns = [
        b'CreateObject', b'WScript.Shell', b'Shell.Application',
        b'Run(', b'Exec(', b'System.', b'Process.Start',
        b'<script', b'javascript:', b'vbscript:'
    ]
    for pattern in executable_patterns:
        if pattern.lower() in file_content.lower():
            errors.append(f"检测到可疑代码特征：{pattern.decode('utf-8', errors='ignore')}")
            break
    
    return errors

# ---------- 文件保存函数（带病毒隔离） ----------
def save_uploaded_file(file_content, filename, user_id):
    """
    保存文件，如果检测到病毒则隔离
    返回：(保存路径, 是否安全, 错误列表)
    """
    # 病毒扫描
    scan_errors = scan_word_document(file_content, filename)
    
    if scan_errors:
        # 有病毒/风险 -> 隔离
        quarantine_name = f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        quarantine_path = os.path.join(VIRUS_SCAN_DIR, quarantine_name)
        with open(quarantine_path, 'wb') as f:
            f.write(file_content)
        log_activity('virus_quarantine', user_id, f"{filename} - {', '.join(scan_errors)}")
        return None, False, scan_errors
    
    # 安全 -> 正常保存
    safe_name = safe_filename(filename, user_id)
    file_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(file_path, 'wb') as f:
        f.write(file_content)
    os.chmod(file_path, 0o444)  # 只读
    return file_path, True, []

def safe_filename(original_name, user_id):
    """生成安全的文件名"""
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

def get_user_key(class_name, student_name):
    """生成用户唯一标识"""
    return f"{class_name}_{student_name}".strip()

# ---------- 页面配置 ----------
st.set_page_config(page_title="比赛作品提交系统", page_icon="🔒")
st.title("📝 比赛作品提交系统")

# ---------- 会话初始化 ----------
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0

# ---------- 登录/注册模块 ----------
if st.session_state.user_id is None:
    st.subheader("👤 登录 / 注册")
    st.caption("请选择你的班级并输入姓名，系统将自动识别你是新用户还是老用户")
    
    col1, col2 = st.columns(2)
    with col1:
        selected_class = st.selectbox("选择班级", CLASS_LIST)
    with col2:
        student_name = st.text_input("真实姓名", max_chars=20, placeholder="张三")
    
    # 自定义班级选项
    use_custom_class = st.checkbox("如果上面没有你的班级，点这里输入")
    if use_custom_class:
        selected_class = st.text_input("手动输入班级", placeholder="例如：初一(5)班")
    
    col3, col4 = st.columns([3, 1])
    with col3:
        agree = st.checkbox("我承诺提交的作品为本人原创")
    with col4:
        st.write("")
    
    if st.button("登录 / 注册", type="primary"):
        # 校验
        errors = []
        if not selected_class:
            errors.append("请选择或输入班级")
        if not student_name:
            errors.append("请输入姓名")
        if not agree:
            errors.append("请勾选原创承诺")
        
        if errors:
            for err in errors:
                st.error(f"❌ {err}")
        else:
            # 生成用户唯一标识
            user_key = get_user_key(selected_class, student_name)
            
            # 检查是否已提交
            data = load_data()
            existing_submission = None
            for s in data['submissions']:
                if s['user_key'] == user_key:
                    existing_submission = s
                    break
            
            if existing_submission:
                st.warning(f"⚠️ {selected_class} {student_name} 已提交过作品，不能重复提交")
                st.info(f"作品名称：{existing_submission.get('work_title', '未知')}")
                st.info(f"提交时间：{existing_submission.get('time', '未知')}")
                st.stop()
            
            # 登录成功
            st.session_state.user_id = user_key
            st.session_state.user_class = selected_class
            st.session_state.user_name = student_name
            log_activity('login_success', user_key)
            st.success(f"✅ 欢迎，{selected_class} {student_name}！")
            st.rerun()
    
    st.stop()

# ---------- 已登录状态 ----------
st.success(f"✅ 当前用户：{st.session_state.user_class} {st.session_state.user_name}")

# ---------- 检查是否已提交（双重检查） ----------
data = load_data()
user_key = st.session_state.user_id
user_submission = None
for s in data['submissions']:
    if s['user_key'] == user_key:
        user_submission = s
        break

if user_submission:
    st.info("📌 你已提交作品，不可重复提交")
    with st.expander("📄 查看我的提交记录"):
        st.write(f"**班级**：{user_submission['class_name']}")
        st.write(f"**姓名**：{user_submission['student_name']}")
        st.write(f"**作品名称**：{user_submission['work_title']}")
        st.write(f"**作品简介**：{user_submission['work_desc']}")
        st.write(f"**提交时间**：{user_submission['time']}")
        if user_submission.get('file_path') and os.path.exists(user_submission['file_path']):
            file_size = os.path.getsize(user_submission['file_path']) / 1024 / 1024
            st.write(f"**附件**：{os.path.basename(user_submission['file_path'])} ({file_size:.2f} MB)")
            # 提供下载（仅本人可下载自己的作品）
            with open(user_submission['file_path'], 'rb') as f:
                st.download_button(
                    label="📥 下载我的作品",
                    data=f,
                    file_name=os.path.basename(user_submission['file_path']),
                    mime="application/msword"
                )
    st.stop()

# ---------- 作品提交表单 ----------
st.subheader("📤 提交你的Word文档作品")
st.caption("⚠️ 仅接受 .doc 或 .docx 格式，文件大小不超过20MB")
st.caption("🔒 系统会自动扫描宏病毒和恶意代码，请确保文档安全")

with st.form("submit_form"):
    # 自动填充班级和姓名
    st.text_input("班级", value=st.session_state.user_class, disabled=True)
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
            st.error(f"❌ 文件大小 {file_size/1024/1024:.1f}MB 超过限制（{MAX_FILE_SIZE/1024/1024}MB）")
        else:
            st.success(f"✅ 已选择文件：{uploaded_file.name} ({file_size/1024:.1f}KB)")
    
    submitted = st.form_submit_button("提交作品", type="primary")

if submitted:
    # ---------- 完整校验 ----------
    errors = []
    
    if not work_title:
        errors.append("作品名称不能为空")
    
    if uploaded_file is None:
        errors.append("请上传Word文档")
    elif uploaded_file.size > MAX_FILE_SIZE:
        errors.append(f"文件大小超过限制")
    else:
        # 读取文件内容
        file_content = uploaded_file.read()
        
        # 病毒扫描
        scan_errors = scan_word_document(file_content, uploaded_file.name)
        if scan_errors:
            errors.append(f"⚠️ 安全检测未通过：{', '.join(scan_errors)}")
            # 记录到隔离区
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
        # ---------- 保存文件 ----------
        try:
            # 保存文件
            safe_name = safe_filename(uploaded_file.name, user_key)
            file_path = os.path.join(UPLOAD_DIR, safe_name)
            with open(file_path, 'wb') as f:
                f.write(file_content)
            os.chmod(file_path, 0o444)
            
            # 保存数据
            data['submissions'].append({
                'user_key': user_key,
                'class_name': st.session_state.user_class,
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
            
            # 显示提交确认
            st.info("📌 你的作品已安全保存，不可修改或重复提交")
            st.redirect(st.page_redirect)  # 刷新页面
            
        except Exception as e:
            log_activity('submit_error', user_key, str(e))
            st.error(f"提交异常，请稍后重试")

# ---------- 管理员后台 ----------
st.sidebar.title("🔐 管理后台")
with st.sidebar.expander("管理员登录"):
    admin_pass = st.text_input("管理员密码", type="password")
    if st.button("验证身份"):
        if verify_admin(admin_pass):
            st.session_state.is_admin = True
            log_activity('admin_login', 'admin', 'success')
            st.success("✅ 验证通过")
        else:
            st.error("❌ 密码错误")
            log_activity('admin_login', 'admin', 'failed')

if st.session_state.get('is_admin', False):
    st.sidebar.divider()
    st.sidebar.subheader(f"📊 统计数据")
    st.sidebar.metric("总参赛人数", len(data['submissions']))
    st.sidebar.metric("隔离文件数", len(os.listdir(VIRUS_SCAN_DIR)) if os.path.exists(VIRUS_SCAN_DIR) else 0)
    
    if data['submissions']:
        df = pd.DataFrame(data['submissions'])
        st.sidebar.dataframe(df[['class_name', 'student_name', 'work_title', 'time']])
        
        # 下载功能
        for idx, row in df.iterrows():
            if row['file_path'] and os.path.exists(row['file_path']):
                with open(row['file_path'], 'rb') as f:
                    st.sidebar.download_button(
                        label=f"📥 {row['student_name']} - {row['work_title']}",
                        data=f,
                        file_name=os.path.basename(row['file_path']),
                        key=f"download_{idx}"
                    )
        
        # 导出数据
        if st.sidebar.button("📤 导出所有数据（JSON）"):
            json_str = json.dumps(data['submissions'], ensure_ascii=False, indent=2)
            st.sidebar.download_button(
                label="下载JSON文件",
                data=json_str,
                file_name=f"参赛数据_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json"
            )
    
    # 查看隔离区
    with st.sidebar.expander("⚠️ 隔离文件列表"):
        if os.path.exists(VIRUS_SCAN_DIR):
            virus_files = os.listdir(VIRUS_SCAN_DIR)
            if virus_files:
                for vf in virus_files:
                    st.sidebar.text(f"🔴 {vf}")
            else:
                st.sidebar.success("✅ 无隔离文件")
    
    if st.sidebar.button("🚪 退出管理"):
        st.session_state.is_admin = False
        st.rerun()

# ---------- 安全提示 ----------
st.sidebar.divider()
st.sidebar.caption("🔒 安全特性：")
st.sidebar.caption("- 仅接受Word文档 (.doc/.docx)")
st.sidebar.caption("- 宏病毒自动扫描")
st.sidebar.caption("- 恶意代码特征检测")
st.sidebar.caption("- 危险文件自动隔离")
st.sidebar.caption("- 文件大小限制 (20MB)")
st.sidebar.caption("- 每人仅限提交一次")
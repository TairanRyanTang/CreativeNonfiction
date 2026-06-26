import streamlit as st
import pandas as pd
import os
import json
import hashlib
import zipfile
import io
import xml.etree.ElementTree as ET
from datetime import datetime

# ---------- 安全配置 ----------
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {'doc', 'docx'}

UPLOAD_DIR = 'uploads'
DATA_FILE = 'data.json'
VIRUS_SCAN_DIR = 'virus_quarantine'

ADMIN_PASSWORD = st.secrets.get("ADMIN_PASSWORD", "password")
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

# ---------- 病毒检测 ----------
def scan_word_document(file_content, filename):
    errors = []
    if filename.lower().endswith('.docx'):
        if file_content[:4] != b'PK\x03\x04':
            errors.append("无效的docx文件格式")
    elif filename.lower().endswith('.doc'):
        if len(file_content) < 8 or file_content[:8] != b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            errors.append("无效的doc文件格式")
    else:
        return ["不支持的文件格式"]
    
    if filename.lower().endswith('.docx'):
        try:
            with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
                for name in zf.namelist():
                    if any(p in name.lower() for p in ['vba', 'macro', 'vbaproject', '_rels/vba', 'word/vba', 'vbaData.xml', 'vbaProject.bin']):
                        errors.append(f"检测到宏文件：{name}")
                        break
        except zipfile.BadZipFile:
            errors.append("docx文件损坏或格式异常")
        except Exception as e:
            errors.append(f"文件解析异常：{str(e)[:50]}")
    
    for sig in [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', b'ObjectPool', b'Embedded', b'objclass']:
        if sig in file_content:
            errors.append("检测到嵌入对象(OLE)，可能存在风险")
            break
    
    if len(file_content) < 1024:
        errors.append("文件过小，可能为空文档或损坏")
    if len(file_content) > 50 * 1024 * 1024:
        errors.append("文件过大，超过50MB限制")
    
    for p in [b'CreateObject', b'WScript.Shell', b'Run(', b'<script', b'eval(']:
        if p.lower() in file_content.lower():
            errors.append(f"检测到可疑代码特征")
            break
    
    return errors

# ---------- 使用标准库读取 docx 文本 ----------
def extract_text_from_docx(file_content):
    """
    从 .docx 文件中提取纯文本（使用 zipfile 和 xml.etree.ElementTree）
    .docx 文件本质是 ZIP 压缩包，文本在 word/document.xml 中
    """
    try:
        text_parts = []
        with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
            # 读取 word/document.xml
            if 'word/document.xml' in zf.namelist():
                xml_content = zf.read('word/document.xml')
                # 解析 XML
                root = ET.fromstring(xml_content)
                # 命名空间
                ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                # 提取所有段落文本
                for paragraph in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                    para_text = []
                    for text_elem in paragraph.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'):
                        if text_elem.text:
                            para_text.append(text_elem.text)
                    if para_text:
                        text_parts.append(''.join(para_text))
                return '\n\n'.join(text_parts)
            else:
                return "⚠️ 文档中未找到 word/document.xml"
    except Exception as e:
        return f"⚠️ 无法解析文档内容：{str(e)[:100]}"

def preview_docx(file_path):
    """读取本地 .docx 文件并返回文本"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return extract_text_from_docx(content)
    except Exception as e:
        return f"⚠️ 读取文件失败：{str(e)[:100]}"

# ---------- 工具函数 ----------
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
            backup = f"data_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            if os.path.exists(DATA_FILE):
                os.rename(DATA_FILE, backup)
            return {'submissions': [], 'users': {}}
    return {'submissions': [], 'users': {}}

def save_data(data):
    temp_file = DATA_FILE + '.tmp'
    with open(temp_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(temp_file, DATA_FILE)

def log_activity(action, user_id, detail=""):
    entry = {
        'time': datetime.now().isoformat(),
        'action': action,
        'user': user_id,
        'detail': detail
    }
    try:
        with open('security.log', 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except:
        pass  # 日志写入失败不影响主流程

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
if 'preview_idx' not in st.session_state:
    st.session_state.preview_idx = None

# ---------- 管理员登录 ----------
if not st.session_state.is_admin:
    with st.expander("🔐 管理员登录"):
        admin_pass = st.text_input("管理员密码", type="password", key="admin_pass")
        if st.button("验证身份"):
            if verify_admin(admin_pass):
                st.session_state.is_admin = True
                log_activity('admin_login', 'admin', 'success')
                st.success("✅ 验证通过，进入管理面板")
                st.rerun()
            else:
                st.error("❌ 密码错误")
                log_activity('admin_login', 'admin', 'failed')

# ========== 管理员模式 ==========
if st.session_state.is_admin:
    st.success("🔓 管理员模式")
    data = load_data()
    
    col1, col2 = st.columns(2)
    col1.metric("总参赛人数", len(data['submissions']))
    virus_cnt = len(os.listdir(VIRUS_SCAN_DIR)) if os.path.exists(VIRUS_SCAN_DIR) else 0
    col2.metric("隔离文件数", virus_cnt)

    if data['submissions']:
        st.subheader("📄 作品列表")
        for idx, row in enumerate(data['submissions']):
            with st.container():
                cols = st.columns([2, 2, 2, 1.5, 1, 1, 1])
                cols[0].write(row.get('student_name', '未知'))
                cols[1].write(row.get('class_name', '未知'))
                cols[2].write(row.get('work_title', '未知'))
                cols[3].write(row.get('time', '')[:16])
                
                # 下载按钮
                if row.get('file_path') and os.path.exists(row['file_path']):
                    with open(row['file_path'], 'rb') as f:
                        cols[4].download_button("⬇️", data=f, 
                                                file_name=os.path.basename(row['file_path']),
                                                key=f"dl_{idx}", help="下载文件")
                else:
                    cols[4].write("无")
                
                # 预览/评分按钮
                if cols[5].button("📖", key=f"prev_{idx}", help="预览文档并评分"):
                    st.session_state.preview_idx = idx
                    st.rerun()
                
                # 显示评分状态
                if row.get('scores'):
                    total = sum(row['scores'].values())
                    cols[6].write(f"已评({total}/20)")
                else:
                    cols[6].write("未评")
        
        # 导出 JSON
        json_str = json.dumps(data['submissions'], ensure_ascii=False, indent=2)
        st.download_button("📤 导出所有数据（JSON）", data=json_str,
                           file_name=f"参赛数据_{datetime.now().strftime('%Y%m%d')}.json",
                           mime="application/json")
    else:
        st.info("暂无提交作品")

    # ---------- 预览与评分区域 ----------
    if st.session_state.preview_idx is not None:
        idx = st.session_state.preview_idx
        if idx < len(data['submissions']):
            sub = data['submissions'][idx]
            st.divider()
            st.subheader(f"📖 预览：{sub.get('student_name', '')} - {sub.get('work_title', '')}")
            
            st.write(f"**年级**：{sub.get('class_name', '')}")
            st.write(f"**简介**：{sub.get('work_desc', '')}")
            
            # 文档预览
            file_path = sub.get('file_path')
            if file_path and os.path.exists(file_path):
                ext = os.path.splitext(file_path)[1].lower()
                if ext == '.docx':
                    with st.spinner("加载文档内容..."):
                        text = preview_docx(file_path)
                        st.text_area("文档内容", text, height=300, disabled=True)
                else:
                    st.warning("⚠️ 不支持在线预览 .doc 格式，请下载后查看。")
            else:
                st.error("文件不存在")
            
            # 评分表单
            st.subheader("✍️ 评分")
            existing_scores = sub.get('scores', {})
            with st.form(key=f"score_form_{idx}"):
                nar = st.number_input("Narration (0-5)", 0, 5, 
                                      value=existing_scores.get('narration', 0), step=1)
                ref = st.number_input("Reflection (0-5)", 0, 5, 
                                      value=existing_scores.get('reflection', 0), step=1)
                ide = st.number_input("Identity - Shaping Personality (0-5)", 0, 5, 
                                      value=existing_scores.get('identity', 0), step=1)
                inti = st.number_input("Intimacy / Authenticity (0-5)", 0, 5, 
                                       value=existing_scores.get('intimacy', 0), step=1)
                mark = st.text_area("Mark / 备注", value=sub.get('mark', ''), height=80)
                
                if st.form_submit_button("💾 保存评分"):
                    data = load_data()
                    for s in data['submissions']:
                        if s.get('file_path') == sub.get('file_path') and s.get('user_key') == sub.get('user_key'):
                            s['scores'] = {
                                'narration': nar,
                                'reflection': ref,
                                'identity': ide,
                                'intimacy': inti
                            }
                            s['mark'] = mark
                            s['scored_time'] = datetime.now().isoformat()
                            break
                    save_data(data)
                    log_activity('score_saved', 'admin', f"评分：{sub.get('student_name', '')} - {sub.get('work_title', '')}")
                    st.success("✅ 评分已保存")
                    st.rerun()
            
            if st.button("关闭预览"):
                st.session_state.preview_idx = None
                st.rerun()

    # 安全日志
    with st.expander("📋 安全日志（最近50条）"):
        if os.path.exists('security.log'):
            with open('security.log', 'r', encoding='utf-8') as f:
                logs = f.readlines()
                if logs:
                    for line in reversed(logs[-50:]):
                        try:
                            e = json.loads(line)
                            st.text(f"{e['time']} - {e['action']} - {e['user']} - {e['detail']}")
                        except:
                            st.text(line.strip())
                else:
                    st.success("✅ 暂无日志")
        else:
            st.info("日志文件尚未生成")

    # 隔离文件
    with st.expander("⚠️ 隔离文件列表"):
        if os.path.exists(VIRUS_SCAN_DIR):
            vfs = os.listdir(VIRUS_SCAN_DIR)
            if vfs:
                for vf in vfs:
                    st.text(f"🔴 {vf}")
            else:
                st.success("✅ 无隔离文件")

    # 危险操作
    st.divider()
    st.error("🧹 危险操作区")
    confirm = st.checkbox("⚠️ 我确认要删除所有作品及文件，此操作不可恢复")
    if st.button("一键删除所有作品", disabled=not confirm):
        if confirm:
            if os.path.exists(UPLOAD_DIR):
                for f in os.listdir(UPLOAD_DIR):
                    os.remove(os.path.join(UPLOAD_DIR, f))
            data['submissions'] = []
            save_data(data)
            log_activity('admin_delete_all', 'admin', 'All deleted')
            st.success("✅ 已清空")
            st.rerun()

    if st.button("🚪 退出管理"):
        st.session_state.is_admin = False
        st.rerun()
    st.stop()

# ========== 学生用户流程 ==========
data = load_data()

if st.session_state.user_id is None:
    st.subheader("👤 学生登录 / 注册")
    col1, col2 = st.columns(2)
    with col1:
        grade = st.selectbox("选择年级", GRADE_LIST)
    with col2:
        name = st.text_input("真实姓名", max_chars=20, placeholder="张三")
    
    use_custom = st.checkbox("如果上面没有你的年级，点这里输入")
    if use_custom:
        grade = st.text_input("手动输入年级", placeholder="例如：Grade 2027")
    
    password = st.text_input("设置/输入密码", type="password")
    agree = st.checkbox("我承诺提交的作品为本人原创")

    if st.button("登录 / 注册", type="primary"):
        if not grade or not name or not password:
            st.error("❌ 请填写所有字段")
        elif not agree:
            st.error("❌ 请勾选原创承诺")
        else:
            user_key = get_user_key(grade, name)
            users = data.setdefault('users', {})
            
            if user_key in users:
                if users[user_key] == hash_password(password):
                    st.session_state.user_id = user_key
                    st.session_state.user_grade = grade
                    st.session_state.user_name = name
                    log_activity('login', user_key)
                    st.success(f"✅ 欢迎回来，{name}！")
                    st.rerun()
                else:
                    st.error("❌ 密码错误，请重试")
            else:
                users[user_key] = hash_password(password)
                save_data(data)
                st.session_state.user_id = user_key
                st.session_state.user_grade = grade
                st.session_state.user_name = name
                log_activity('register', user_key)
                st.success(f"✅ 注册成功，{name}！")
                st.rerun()
    st.stop()

# 已登录学生
st.success(f"✅ 当前用户：{st.session_state.user_grade} {st.session_state.user_name}")

user_key = st.session_state.user_id
my_sub = None
for s in data['submissions']:
    if s['user_key'] == user_key:
        my_sub = s
        break

# 显示评分
if my_sub and my_sub.get('scores'):
    st.subheader("📊 你的评分结果")
    scores = my_sub['scores']
    total = sum(scores.values())
    st.metric("总分", f"{total} / 20")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Narration", f"{scores['narration']}/5")
    col2.metric("Reflection", f"{scores['reflection']}/5")
    col3.metric("Identity", f"{scores['identity']}/5")
    col4.metric("Intimacy", f"{scores['intimacy']}/5")
    
    if my_sub.get('mark'):
        st.info(f"💬 评语：{my_sub['mark']}")

# 提交表单
if my_sub:
    st.warning("⚠️ 你已有作品，再次提交将覆盖之前的作品。")
    with st.expander("📄 查看我的作品信息"):
        st.write(f"**年级**：{my_sub['class_name']}")
        st.write(f"**作品名称**：{my_sub['work_title']}")
        st.write(f"**提交时间**：{my_sub['time']}")

st.subheader("📤 提交/更新作品")
with st.form("submit_form"):
    st.text_input("年级", value=st.session_state.user_grade, disabled=True)
    st.text_input("姓名", value=st.session_state.user_name, disabled=True)
    work_title = st.text_input("作品名称", max_chars=100, placeholder="《我的参赛作品》")
    work_desc = st.text_area("作品简介", max_chars=500, placeholder="请简要描述...")
    uploaded_file = st.file_uploader("上传Word文档（.doc/.docx）", type=['doc', 'docx'])
    
    if uploaded_file:
        if uploaded_file.size > MAX_FILE_SIZE:
            st.error("❌ 文件超过20MB限制")
        else:
            st.success(f"✅ 已选择：{uploaded_file.name} ({uploaded_file.size/1024:.1f}KB)")
    
    if st.form_submit_button("提交作品", type="primary"):
        if not work_title:
            st.error("❌ 作品名称不能为空")
        elif not uploaded_file:
            st.error("❌ 请上传文件")
        elif uploaded_file.size > MAX_FILE_SIZE:
            st.error("❌ 文件过大")
        else:
            content = uploaded_file.read()
            scan_err = scan_word_document(content, uploaded_file.name)
            
            if scan_err:
                st.error(f"⛔ 安全检测未通过：{', '.join(scan_err)}")
                qname = f"{user_key}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uploaded_file.name}"
                with open(os.path.join(VIRUS_SCAN_DIR, qname), 'wb') as f:
                    f.write(content)
                log_activity('virus_blocked', user_key, qname)
            else:
                try:
                    data = load_data()
                    # 删除旧文件
                    for i, s in enumerate(data['submissions']):
                        if s['user_key'] == user_key:
                            if s.get('file_path') and os.path.exists(s['file_path']):
                                os.remove(s['file_path'])
                            data['submissions'].pop(i)
                            break
                    
                    # 保存新文件
                    fname = safe_filename(uploaded_file.name, user_key)
                    fpath = os.path.join(UPLOAD_DIR, fname)
                    with open(fpath, 'wb') as f:
                        f.write(content)
                    
                    # 添加新记录
                    new_sub = {
                        'user_key': user_key,
                        'class_name': st.session_state.user_grade,
                        'student_name': st.session_state.user_name,
                        'work_title': work_title,
                        'work_desc': work_desc,
                        'file_path': fpath,
                        'file_size': uploaded_file.size,
                        'file_type': uploaded_file.type,
                        'time': datetime.now().isoformat()
                    }
                    data['submissions'].append(new_sub)
                    save_data(data)
                    log_activity('submit_success', user_key, work_title)
                    st.success("🎉 作品提交成功！")
                    st.balloons()
                    st.rerun()
                except Exception as e:
                    log_activity('submit_error', user_key, str(e))
                    st.error(f"提交异常：{str(e)[:100]}")

# 侧边栏
st.sidebar.divider()
st.sidebar.caption("🔒 安全特性：")
st.sidebar.caption("- 仅接受Word文档")
st.sidebar.caption("- 宏病毒自动扫描")
st.sidebar.caption("- 恶意代码检测")
st.sidebar.caption("- 危险文件隔离")
st.sidebar.caption("- 20MB大小限制")
st.sidebar.caption("- 可覆盖提交")

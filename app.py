import streamlit as st
import pandas as pd
import os
import json
import hashlib
import zipfile
import io
import xml.etree.ElementTree as ET
from datetime import datetime
import shutil
import tempfile
import base64

# ---------- 安全配置 ----------
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {'doc', 'docx'}

UPLOAD_DIR = '/tmp/uploads'
DATA_FILE = '/tmp/data.json'
VIRUS_SCAN_DIR = '/tmp/virus_quarantine'

ADMIN_PASSWORD = st.secrets.get("ADMIN_PASSWORD", "password")
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

GRADE_LIST = ['Grade 2027', 'Grade 2028', 'Grade 2029']

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(VIRUS_SCAN_DIR, exist_ok=True)

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
                    if any(p in name.lower() for p in ['vba', 'macro', 'vbaproject', 'word/vba', 'vbaData.xml', 'vbaProject.bin']):
                        errors.append(f"检测到宏文件：{name}")
                        break
        except:
            errors.append("文件损坏")
    if len(file_content) < 1024:
        errors.append("文件过小")
    if len(file_content) > 50*1024*1024:
        errors.append("文件过大")
    return errors

# ---------- docx 文本提取 ----------
def extract_text_from_docx(file_content):
    try:
        text_parts = []
        with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
            if 'word/document.xml' in zf.namelist():
                xml_content = zf.read('word/document.xml')
                root = ET.fromstring(xml_content)
                ns = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
                for p in root.iter(f'{{{ns}}}p'):
                    para_text = []
                    for t in p.iter(f'{{{ns}}}t'):
                        if t.text:
                            para_text.append(t.text)
                    if para_text:
                        text_parts.append(''.join(para_text))
                return '\n\n'.join(text_parts)
        return "⚠️ 无法读取文档内容"
    except Exception as e:
        return f"⚠️ 解析错误：{str(e)[:100]}"

def preview_docx(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return extract_text_from_docx(content)
    except:
        return "⚠️ 文件读取失败"

# ---------- 工具函数 ----------
def safe_filename(original_name, user_id):
    ext = original_name.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("不支持的文件类型")
    ts = datetime.now().strftime('%Y%m%d%H%M%S%f')
    return f"{user_id}_{ts}.{ext}"

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def verify_admin(p):
    return hash_password(p) == ADMIN_PASSWORD_HASH

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {'submissions': [], 'users': {}}
    return {'submissions': [], 'users': {}}

def log_activity(action, user_id, detail=""):
    entry = {'time': datetime.now().isoformat(), 'action': action, 'user': user_id, 'detail': detail}
    print(json.dumps(entry, ensure_ascii=False))

def get_user_key(grade, name):
    return f"{grade}_{name}".strip()

# ---------- GitHub 备份与恢复（缓存模式） ----------
CACHE_PATH = "cache/backup_latest.zip"  # 固定缓存路径

def restore_from_github():
    """从 GitHub 缓存中恢复数据（ZIP 格式）"""
    print("🔍 restore_from_github: 检查是否需要从 GitHub 缓存恢复...")
    try:
        from github import Github, Auth
        token = st.secrets.get("GITHUB_TOKEN")
        repo_name = st.secrets.get("GITHUB_REPO")
        if not token or not repo_name:
            print("ℹ️ 未配置 GitHub，跳过恢复")
            return

        if os.path.exists(DATA_FILE):
            print("✅ 本地数据已存在，无需恢复")
            return

        print("⚠️ 本地数据缺失，尝试从 GitHub 缓存恢复...")
        g = Github(auth=Auth.Token(token))
        repo = g.get_repo(repo_name)

        try:
            # 获取缓存文件
            contents = repo.get_contents(CACHE_PATH)
            zip_bytes = base64.b64decode(contents.content)
            print(f"📦 找到缓存文件: {CACHE_PATH}")

            # 解压 ZIP
            with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
                # 恢复 data.json
                if 'data.json' in zf.namelist():
                    zf.extract('data.json', '/tmp')
                    print("✅ data.json 已恢复")
                else:
                    raise ValueError("缓存中缺少 data.json")

                # 恢复 uploads 目录
                if os.path.exists(UPLOAD_DIR):
                    shutil.rmtree(UPLOAD_DIR)
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                for member in zf.namelist():
                    if member.startswith('uploads/') and not member.endswith('/'):
                        zf.extract(member, '/tmp')
                print("✅ uploads 已恢复")

            log_activity('github_restore_success', 'system', 'Restored from cache')
        except Exception as e:
            print(f"❌ 恢复失败: {str(e)[:200]}")
            log_activity('github_restore_failed', 'system', str(e)[:200])
    except Exception as e:
        print(f"❌ restore_from_github 异常: {str(e)[:200]}")

def backup_to_github(data):
    """生成最新数据 ZIP 并上传到 GitHub cache/ 目录，删除旧缓存"""
    print("🔄 backup_to_github: 开始缓存备份...")
    try:
        from github import Github, Auth
        token = st.secrets.get("GITHUB_TOKEN")
        repo_name = st.secrets.get("GITHUB_REPO")
        if not token or not repo_name:
            msg = "ℹ️ GitHub 未配置，跳过备份"
            print(msg)
            st.session_state.backup_msg = msg
            return

        g = Github(auth=Auth.Token(token))
        repo = g.get_repo(repo_name)

        # 1. 打包 data.json 和 uploads 目录为 ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 写入 data.json
            zf.writestr('data.json', json.dumps(data, ensure_ascii=False, indent=2))
            # 写入 uploads 目录所有文件
            if os.path.exists(UPLOAD_DIR):
                for root, dirs, files in os.walk(UPLOAD_DIR):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.join('uploads', os.path.relpath(file_path, UPLOAD_DIR))
                        zf.write(file_path, arcname)

        zip_content = zip_buffer.getvalue()
        content_b64 = base64.b64encode(zip_content).decode()

        # 2. 删除旧缓存（如果存在）
        try:
            old = repo.get_contents(CACHE_PATH)
            repo.delete_file(old.path, "删除旧缓存", old.sha)
            print("🗑️ 已删除旧缓存文件")
        except:
            print("ℹ️ 无旧缓存需要删除")

        # 3. 上传新缓存
        repo.create_file(CACHE_PATH, f"缓存备份 {datetime.now().isoformat()}", content_b64)
        msg = f"✅ 缓存已更新至 GitHub ({CACHE_PATH})"
        print(msg)
        st.session_state.backup_msg = msg
        log_activity('github_backup_success', 'system', 'Cache updated')
    except Exception as e:
        msg = f"❌ 缓存备份失败：{str(e)[:200]}"
        print(msg)
        st.session_state.backup_msg = msg
        log_activity('github_backup_failed', 'system', str(e)[:200])

def save_data(data):
    """保存数据到本地 JSON，不再自动触发备份"""
    print("💾 save_data: 保存数据到本地...")
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_FILE)
    print("✅ 数据已写入本地")

# ---------- 手动备份/恢复（下载/上传） ----------
def create_backup_zip(data):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('data.json', json.dumps(data, ensure_ascii=False, indent=2))
        if os.path.exists(UPLOAD_DIR):
            for root, dirs, files in os.walk(UPLOAD_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, UPLOAD_DIR)
                    zf.write(file_path, os.path.join('uploads', arcname))
    return zip_buffer.getvalue()

def restore_backup_zip(zip_bytes):
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        if 'data.json' not in zf.namelist():
            raise ValueError("备份文件中缺少 data.json")
        with zf.open('data.json') as f:
            new_data = json.load(f)
            if 'submissions' not in new_data or 'users' not in new_data:
                raise ValueError("data.json 格式不正确")
        if os.path.exists(UPLOAD_DIR):
            shutil.rmtree(UPLOAD_DIR)
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        for member in zf.namelist():
            if member == 'data.json':
                continue
            if not member.startswith('uploads/'):
                continue
            target_path = os.path.join('/tmp', member)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(member) as source, open(target_path, 'wb') as target:
                shutil.copyfileobj(source, target)
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, ensure_ascii=False, indent=2)
    return True

# ---------- 应用启动时自动恢复 ----------
restore_from_github()

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
if 'submit_success' not in st.session_state:
    st.session_state.submit_success = False
if 'backup_msg' not in st.session_state:
    st.session_state.backup_msg = ""

# ---------- 管理员登录 ----------
if not st.session_state.is_admin:
    with st.expander("🔐 管理员登录"):
        admin_pass = st.text_input("管理员密码", type="password", key="admin_pass")
        if st.button("验证身份", key="admin_login_btn"):
            if verify_admin(admin_pass):
                st.session_state.is_admin = True
                log_activity('admin_login', 'admin', 'success')
                st.success("✅ 验证通过")
                st.rerun()
            else:
                st.error("❌ 密码错误")

# ========== 管理员模式 ==========
if st.session_state.is_admin:
    st.success("🔓 管理员模式")
    data = load_data()

    # 备份与恢复区域
    st.subheader("💾 数据备份与恢复")
    col_bkp1, col_bkp2 = st.columns(2)
    with col_bkp1:
        if st.button("📥 一键备份所有数据（下载ZIP）"):
            zip_data = create_backup_zip(data)
            st.download_button(
                label="下载备份文件",
                data=zip_data,
                file_name=f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip",
                key="backup_download"
            )
            st.success("备份文件已生成，点击上方按钮下载")
    with col_bkp2:
        uploaded_backup = st.file_uploader("📤 上传备份文件恢复", type="zip", key="restore_zip")
        if uploaded_backup is not None:
            if st.button("确认恢复备份", key="confirm_restore"):
                try:
                    restore_backup_zip(uploaded_backup.read())
                    st.success("✅ 数据恢复成功！请刷新页面查看")
                    log_activity('admin_restore', 'admin', '成功恢复备份')
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ 恢复失败：{str(e)}")

    # 手动备份到 GitHub（现在改为立即更新缓存）
    st.divider()
    st.subheader("☁️ 手动更新 GitHub 缓存")
    if st.button("📤 立即更新缓存到 GitHub"):
        with st.spinner("正在更新缓存..."):
            backup_to_github(data)
        if "✅" in st.session_state.backup_msg:
            st.success(st.session_state.backup_msg)
        elif "❌" in st.session_state.backup_msg:
            st.error(st.session_state.backup_msg)
        else:
            st.info(st.session_state.backup_msg)
    st.caption(f"最近缓存状态：{st.session_state.backup_msg}")

    st.divider()

    # 统计数据
    col1, col2 = st.columns(2)
    col1.metric("总参赛人数", len(data['submissions']))
    virus_cnt = len(os.listdir(VIRUS_SCAN_DIR)) if os.path.exists(VIRUS_SCAN_DIR) else 0
    col2.metric("隔离文件数", virus_cnt)

    # 作品列表
    if data['submissions']:
        st.subheader("📄 作品列表")
        for idx, row in enumerate(data['submissions']):
            with st.container():
                cols = st.columns([2, 2, 2, 1.5, 1, 1, 1])
                cols[0].write(row.get('student_name', '未知'))
                cols[1].write(row.get('class_name', '未知'))
                title = row.get('work_title', '未知')
                if row.get('flagged'):
                    cols[2].markdown(f"<span style='color:red'>{title}</span>", unsafe_allow_html=True)
                else:
                    cols[2].write(title)
                cols[3].write(row.get('time', '')[:16])
                if row.get('file_path') and os.path.exists(row['file_path']):
                    with open(row['file_path'], 'rb') as f:
                        cols[4].download_button("⬇️", data=f, file_name=os.path.basename(row['file_path']), key=f"dl_{idx}")
                else:
                    cols[4].write("无")
                if cols[5].button("📖", key=f"prev_{idx}"):
                    st.session_state.preview_idx = idx
                    st.rerun()
                if row.get('scores'):
                    total = sum(row['scores'].values())
                    cols[6].write(f"已评({total}/20)")
                else:
                    cols[6].write("未评")

        json_str = json.dumps(data['submissions'], ensure_ascii=False, indent=2)
        st.download_button("📤 仅导出提交数据 (JSON)", data=json_str,
                           file_name=f"submissions_{datetime.now().strftime('%Y%m%d')}.json",
                           mime="application/json")
    else:
        st.info("暂无提交作品")

    # 预览与评分
    if st.session_state.preview_idx is not None:
        idx = st.session_state.preview_idx
        if idx < len(data['submissions']):
            sub = data['submissions'][idx]
            st.divider()
            st.subheader(f"📖 {sub.get('student_name', '')} - {sub.get('work_title', '')}")
            st.write(f"**年级**：{sub.get('class_name', '')}")
            st.write(f"**简介**：{sub.get('work_desc', '')}")
            file_path = sub.get('file_path')
            if file_path and os.path.exists(file_path):
                ext = os.path.splitext(file_path)[1].lower()
                if ext == '.docx':
                    with st.spinner("加载文档..."):
                        text = preview_docx(file_path)
                        st.text_area("文档内容", text, height=300, disabled=True)
                else:
                    st.warning("不支持预览 .doc 格式，请下载查看")
            else:
                st.error("文件不存在")

            st.subheader("✍️ 评分")
            existing_scores = sub.get('scores', {})
            with st.form(key=f"score_{idx}"):
                nar = st.number_input("Narration (0-5)", 0, 5, value=existing_scores.get('narration', 0))
                ref = st.number_input("Reflection (0-5)", 0, 5, value=existing_scores.get('reflection', 0))
                ide = st.number_input("Identity (0-5)", 0, 5, value=existing_scores.get('identity', 0))
                inti = st.number_input("Intimacy / Authenticity (0-5)", 0, 5, value=existing_scores.get('intimacy', 0))
                if st.form_submit_button("保存评分"):
                    data = load_data()
                    for s in data['submissions']:
                        if s.get('file_path') == sub.get('file_path') and s.get('user_key') == sub.get('user_key'):
                            s['scores'] = {'narration': nar, 'reflection': ref, 'identity': ide, 'intimacy': inti}
                            break
                    save_data(data)
                    backup_to_github(data)  # 评分时缓存
                    st.success("✅ 评分已保存")
                    st.rerun()

            # 标记待复核
            st.divider()
            flagged = sub.get('flagged', False)
            if flagged:
                if st.button("✅ 取消标记（已复核）"):
                    data = load_data()
                    for s in data['submissions']:
                        if s.get('file_path') == sub.get('file_path') and s.get('user_key') == sub.get('user_key'):
                            s['flagged'] = False
                            break
                    save_data(data)
                    backup_to_github(data)  # 标记操作时缓存
                    st.success("已取消标记")
                    st.rerun()
            else:
                if st.button("🚩 标记为待复核"):
                    data = load_data()
                    for s in data['submissions']:
                        if s.get('file_path') == sub.get('file_path') and s.get('user_key') == sub.get('user_key'):
                            s['flagged'] = True
                            break
                    save_data(data)
                    backup_to_github(data)
                    st.success("已标记为待复核")
                    st.rerun()

            if st.button("关闭预览"):
                st.session_state.preview_idx = None
                st.rerun()

    # 隔离区与日志
    with st.expander("⚠️ 隔离文件列表"):
        if os.path.exists(VIRUS_SCAN_DIR):
            vfs = os.listdir(VIRUS_SCAN_DIR)
            if vfs:
                for vf in vfs:
                    st.text(f"🔴 {vf}")
            else:
                st.success("✅ 无隔离文件")

    with st.expander("📋 最近日志（控制台输出）"):
        st.write("请查看 Streamlit Cloud 的 'Manage app' → 'Logs' 获取详细日志")

    # 危险操作：清空所有
    st.divider()
    st.error("🧹 危险操作区")
    confirm = st.checkbox("⚠️ 我确认要删除所有作品及文件，此操作不可恢复")
    if st.button("一键删除所有作品", disabled=not confirm):
        if confirm:
            if os.path.exists(UPLOAD_DIR):
                shutil.rmtree(UPLOAD_DIR)
                os.makedirs(UPLOAD_DIR, exist_ok=True)
            data['submissions'] = []
            save_data(data)
            backup_to_github(data)  # 清空时也缓存
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
    use_custom = st.checkbox("手动输入年级")
    if use_custom:
        grade = st.text_input("输入年级", placeholder="Grade 2027")
    password = st.text_input("设置/输入密码", type="password")
    agree = st.checkbox("我承诺提交的作品为本人原创")

    if st.button("登录 / 注册", type="primary"):
        if not grade or not name or not password or not agree:
            st.error("请填写所有字段并勾选承诺")
        else:
            user_key = get_user_key(grade, name)
            users = data.setdefault('users', {})
            if user_key in users:
                if users[user_key] == hash_password(password):
                    st.session_state.user_id = user_key
                    st.session_state.user_grade = grade
                    st.session_state.user_name = name
                    log_activity('login', user_key)
                    # 登录不触发备份
                    st.success(f"欢迎回来，{name}！")
                    st.rerun()
                else:
                    st.error("密码错误")
            else:
                users[user_key] = hash_password(password)
                save_data(data)
                backup_to_github(data)  # 新用户注册时备份
                st.session_state.user_id = user_key
                st.session_state.user_grade = grade
                st.session_state.user_name = name
                log_activity('register', user_key)
                st.success(f"注册成功，{name}！")
                st.rerun()
    st.stop()

# 已登录学生
st.success(f"当前用户：{st.session_state.user_grade} {st.session_state.user_name}")

if st.button("🚪 退出登录"):
    st.session_state.user_id = None
    st.session_state.user_grade = None
    st.session_state.user_name = None
    st.session_state.submit_success = False
    st.rerun()

# 提交成功页面
if st.session_state.submit_success:
    st.balloons()
    st.title("🎉 作品提交成功！")
    data = load_data()
    user_key = st.session_state.user_id
    my_sub = None
    for s in data['submissions']:
        if s['user_key'] == user_key:
            my_sub = s
            break

    if my_sub:
        st.subheader("📄 提交作品详情")
        st.write(f"**作品名称**：{my_sub.get('work_title', '未知')}")
        st.write(f"**作品简介**：{my_sub.get('work_desc', '无')}")
        st.write(f"**提交时间**：{my_sub.get('time', '未知')}")
        st.write(f"**文件名**：{os.path.basename(my_sub.get('file_path', ''))}")
        if my_sub.get('scores'):
            scores = my_sub['scores']
            total = sum(scores.values())
            st.info(f"📊 当前评分：{total} / 20")
        else:
            st.info("📊 尚未评分，请耐心等待管理员评审")
    else:
        st.warning("未找到作品记录，请联系管理员")

    if st.button("🔙 返回登录", type="primary"):
        st.session_state.user_id = None
        st.session_state.user_grade = None
        st.session_state.user_name = None
        st.session_state.submit_success = False
        st.rerun()
    st.stop()

# 显示评分
user_key = st.session_state.user_id
my_sub = None
for s in data['submissions']:
    if s['user_key'] == user_key:
        my_sub = s
        break

if my_sub and my_sub.get('scores'):
    st.subheader("📊 你的评分")
    scores = my_sub['scores']
    total = sum(scores.values())
    st.metric("总分", f"{total} / 20")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Narration", f"{scores['narration']}/5")
    c2.metric("Reflection", f"{scores['reflection']}/5")
    c3.metric("Identity", f"{scores['identity']}/5")
    c4.metric("Intimacy", f"{scores['intimacy']}/5")

if my_sub:
    st.warning("你已有作品，再次提交将覆盖之前的作品。")
    with st.expander("查看我的作品信息"):
        st.write(f"年级：{my_sub['class_name']}")
        st.write(f"作品名：{my_sub['work_title']}")
        st.write(f"提交时间：{my_sub['time']}")

st.subheader("📤 提交/更新作品")
with st.form("submit_form"):
    st.text_input("年级", value=st.session_state.user_grade, disabled=True)
    st.text_input("姓名", value=st.session_state.user_name, disabled=True)
    work_title = st.text_input("作品名称", max_chars=100)
    work_desc = st.text_area("作品简介", max_chars=500)
    uploaded_file = st.file_uploader("上传Word文档 (.doc/.docx)", type=['doc', 'docx'])
    if uploaded_file:
        if uploaded_file.size > MAX_FILE_SIZE:
            st.error("文件超过20MB")
        else:
            st.success(f"已选择：{uploaded_file.name} ({uploaded_file.size/1024:.1f}KB)")

    if st.form_submit_button("提交作品", type="primary"):
        if not work_title:
            st.error("作品名称不能为空")
        elif not uploaded_file:
            st.error("请上传文件")
        elif uploaded_file.size > MAX_FILE_SIZE:
            st.error("文件过大")
        else:
            content = uploaded_file.read()
            scan_err = scan_word_document(content, uploaded_file.name)
            if scan_err:
                st.error(f"安全检测未通过：{', '.join(scan_err)}")
                qname = f"{user_key}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uploaded_file.name}"
                with open(os.path.join(VIRUS_SCAN_DIR, qname), 'wb') as f:
                    f.write(content)
                log_activity('virus_blocked', user_key, qname)
            else:
                try:
                    data = load_data()
                    for i, s in enumerate(data['submissions']):
                        if s['user_key'] == user_key:
                            if s.get('file_path') and os.path.exists(s['file_path']):
                                os.remove(s['file_path'])
                            data['submissions'].pop(i)
                            break
                    fname = safe_filename(uploaded_file.name, user_key)
                    fpath = os.path.join(UPLOAD_DIR, fname)
                    with open(fpath, 'wb') as f:
                        f.write(content)
                    new_sub = {
                        'user_key': user_key,
                        'class_name': st.session_state.user_grade,
                        'student_name': st.session_state.user_name,
                        'work_title': work_title,
                        'work_desc': work_desc,
                        'file_path': fpath,
                        'file_size': uploaded_file.size,
                        'time': datetime.now().isoformat()
                    }
                    data['submissions'].append(new_sub)
                    save_data(data)
                    backup_to_github(data)  # 提交作品时缓存
                    log_activity('submit_success', user_key, work_title)
                    st.session_state.submit_success = True
                    st.rerun()
                except Exception as e:
                    st.error(f"提交异常：{str(e)[:100]}")

# 侧边栏
st.sidebar.divider()
st.sidebar.caption("📦 GitHub 缓存状态：")
if st.session_state.backup_msg:
    st.sidebar.info(st.session_state.backup_msg)
else:
    st.sidebar.caption("暂无缓存记录")
st.sidebar.divider()
st.sidebar.caption("🔒 安全特性：")
st.sidebar.caption("- 仅接受Word文档 (.doc/.docx)")
st.sidebar.caption("- 宏病毒自动扫描")
st.sidebar.caption("- 恶意代码检测")
st.sidebar.caption("- 危险文件自动隔离")
st.sidebar.caption("- 文件大小限制 (20MB)")
st.sidebar.caption("- 提交可覆盖，以最新为准")

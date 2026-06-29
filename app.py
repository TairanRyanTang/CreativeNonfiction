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

# 从 Secrets 读取管理员密码（若未设置则默认 "password"）
ADMIN_PASSWORD = st.secrets.get("ADMIN_PASSWORD", "password")
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

GRADE_LIST = ['Grade 2027', 'Grade 2028', 'Grade 2029']

# 创建必要目录
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(VIRUS_SCAN_DIR, exist_ok=True)

print("🚀 应用启动，目录已创建")

# ---------- 病毒检测 ----------
def scan_word_document(file_content, filename):
    # ... 保持不变 ...
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

# ---------- docx 文本提取（标准库） ----------
def extract_text_from_docx(file_content):
    # ... 保持不变 ...
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
    # ... 保持不变 ...
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
            print(f"❌ load_data 解析失败，使用空数据")
            return {'submissions': [], 'users': {}}
    return {'submissions': [], 'users': {}}

def log_activity(action, user_id, detail=""):
    entry = {'time': datetime.now().isoformat(), 'action': action, 'user': user_id, 'detail': detail}
    print(json.dumps(entry, ensure_ascii=False))

def get_user_key(grade, name):
    return f"{grade}_{name}".strip()

# ---------- GitHub 自动备份与恢复 ----------
def restore_from_github():
    print("🔍 restore_from_github: 开始检查是否需要恢复数据...")
    try:
        from github import Github
        token = st.secrets.get("GITHUB_TOKEN")
        repo_name = st.secrets.get("GITHUB_REPO")
        if not token or not repo_name:
            print("ℹ️ 未配置 GitHub 备份，跳过恢复")
            return

        # 只在本地数据文件丢失时才恢复
        if os.path.exists(DATA_FILE):
            print(f"✅ 本地数据文件 {DATA_FILE} 已存在，无需恢复")
            return

        print(f"⚠️ 本地数据文件缺失，尝试从 GitHub 恢复...")
        g = Github(token)
        repo = g.get_repo(repo_name)
        print(f"📡 已连接仓库: {repo_name}")

        contents = repo.get_contents("")
        print(f"📂 仓库内容列表获取成功，共 {len(contents)} 个对象")

        data_files = []
        zip_files = []
        for c in contents:
            if c.name.startswith("backup_") and c.name.endswith("_data.json"):
                data_files.append(c)
            elif c.name.startswith("backup_") and c.name.endswith("_uploads.zip"):
                zip_files.append(c)

        print(f"🔎 找到 data 备份 {len(data_files)} 个, uploads 备份 {len(zip_files)} 个")
        if not data_files:
            print("❌ 没有任何备份文件，无法恢复")
            return

        data_files.sort(key=lambda x: x.name, reverse=True)
        zip_files.sort(key=lambda x: x.name, reverse=True)

        latest_data = data_files[0]
        print(f"⬇️ 正在恢复数据: {latest_data.name}")
        data_content = base64.b64decode(latest_data.content).decode('utf-8')
        new_data = json.loads(data_content)
        if 'submissions' in new_data and 'users' in new_data:
            with open(DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(new_data, f, ensure_ascii=False, indent=2)
            print(f"✅ data.json 已写入，包含 {len(new_data['submissions'])} 个作品")
            log_activity('github_restore_data', 'system', f'Restored {latest_data.name}')
        else:
            raise ValueError("data.json 格式不正确")

        if zip_files:
            if not os.path.exists(UPLOAD_DIR):
                os.makedirs(UPLOAD_DIR, exist_ok=True)
            latest_zip = zip_files[0]
            print(f"⬇️ 正在恢复上传文件: {latest_zip.name}")
            zip_bytes = base64.b64decode(latest_zip.content)
            with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
                zf.extractall(UPLOAD_DIR)
            print(f"✅ 上传文件已解压到 {UPLOAD_DIR}")
            log_activity('github_restore_uploads', 'system', f'Restored {latest_zip.name}')
        else:
            print("ℹ️ 没有上传文件备份，跳过")

    except Exception as e:
        print(f"❌ restore_from_github 失败: {str(e)[:200]}")
        log_activity('github_restore_failed', 'system', str(e)[:200])

def backup_to_github(data):
    print("🔄 backup_to_github: 开始备份...")
    try:
        from github import Github
        token = st.secrets.get("GITHUB_TOKEN")
        repo_name = st.secrets.get("GITHUB_REPO")
        if not token or not repo_name:
            print("ℹ️ GitHub 未配置，跳过备份")
            return

        g = Github(token)
        repo = g.get_repo(repo_name)
        print(f"📡 已连接仓库: {repo_name}")

        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        print(f"📊 准备上传 data.json (大小: {len(json_str)} 字符)")

        uploads_zip_bytes = None
        if os.path.exists(UPLOAD_DIR) and os.listdir(UPLOAD_DIR):
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(UPLOAD_DIR):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zf.write(file_path, file)
            uploads_zip_bytes = zip_buffer.getvalue()
            print(f"📦 打包 uploads 完成，大小: {len(uploads_zip_bytes)} 字节")
        else:
            print("ℹ️ uploads 目录为空或无文件，不打包")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        data_filename = f"backup_{timestamp}_data.json"
        print(f"⬆️ 上传 {data_filename}...")
        repo.create_file(data_filename, f"Backup data at {timestamp}", json_str)
        print(f"✅ {data_filename} 上传成功")

        if uploads_zip_bytes:
            content_b64 = base64.b64encode(uploads_zip_bytes).decode()
            zip_filename = f"backup_{timestamp}_uploads.zip"
            print(f"⬆️ 上传 {zip_filename} (base64 长度: {len(content_b64)})...")
            repo.create_file(zip_filename, f"Backup uploads at {timestamp}", content_b64)
            print(f"✅ {zip_filename} 上传成功")

        # 清理旧备份
        print("🧹 开始清理旧备份（最多保留 10 个）...")
        contents = repo.get_contents("")
        backup_files = [c for c in contents if c.name.startswith("backup_")]
        backup_files.sort(key=lambda x: x.name, reverse=True)
        data_files = [f for f in backup_files if f.name.endswith("_data.json")]
        zip_files = [f for f in backup_files if f.name.endswith("_uploads.zip")]
        for old_file in data_files[10:]:
            repo.delete_file(old_file.path, "Cleanup old backup", old_file.sha)
            print(f"🗑️ 删除旧数据备份: {old_file.path}")
        for old_file in zip_files[10:]:
            repo.delete_file(old_file.path, "Cleanup old backup", old_file.sha)
            print(f"🗑️ 删除旧上传备份: {old_file.path}")
        print("✅ 清理完成")

        log_activity('github_backup_success', 'system', f'Backup {timestamp}')
    except Exception as e:
        print(f"❌ backup_to_github 失败: {str(e)[:200]}")
        log_activity('github_backup_failed', 'system', str(e)[:200])

def save_data(data):
    print("💾 save_data: 保存数据到本地...")
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_FILE)
    print(f"✅ 数据已写入 {DATA_FILE}")

    # 自动备份到 GitHub（每分钟最多一次）
    try:
        if 'last_backup_time' not in st.session_state:
            st.session_state.last_backup_time = None
        now = datetime.now()
        if (st.session_state.last_backup_time is None
            or (now - st.session_state.last_backup_time).total_seconds() > 60):
            print(f"⏰ 距上次备份超过 60 秒（上次: {st.session_state.last_backup_time}），触发备份")
            backup_to_github(data)
            st.session_state.last_backup_time = now
        else:
            print(f"⏳ 距上次备份不足 60 秒，跳过备份")
    except Exception as e:
        print(f"❌ save_data 中备份触发失败: {str(e)[:200]}")
        log_activity('github_backup_trigger_failed', 'system', str(e)[:200])

# ---------- 备份/恢复函数（手动下载/上传） ----------
def create_backup_zip(data):
    # ... 保持不变 ...
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
    # ... 保持不变 ...
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        if 'data.json' not in zf.namelist():
            raise ValueError("备份文件中缺少 data.json")
        with zf.open('data.json') as f:
            try:
                new_data = json.load(f)
                if 'submissions' not in new_data or 'users' not in new_data:
                    raise ValueError("data.json 格式不正确")
            except json.JSONDecodeError:
                raise ValueError("data.json 不是有效的 JSON")
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

# ---------- 应用启动时自动恢复数据 ----------
print("🔧 准备执行启动恢复...")
restore_from_github()
print("🔧 启动恢复流程结束")

# ---------- 页面配置 ----------
st.set_page_config(page_title="比赛作品提交系统", page_icon="🔒")
st.title("📝 比赛作品提交系统")

# ... 后续 UI 代码保持不变 ...

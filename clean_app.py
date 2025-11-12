#!/usr/bin/env python3
"""
清理应用数据脚本
用于在部署前清理数据库和上传文件
"""
import os
import shutil

# 定义路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATHS = [
    os.path.join(BASE_DIR, 'imageshare.db'),
    os.path.join(BASE_DIR, 'app', 'imageshare.db')
]
UPLOAD_DIRS = [
    os.path.join(BASE_DIR, 'static', 'uploads'),
    os.path.join(BASE_DIR, 'app', 'static', 'uploads')
]

def clean_databases():
    """清理数据库文件"""
    print("正在清理数据库文件...")
    for db_path in DB_PATHS:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
                print(f"已删除: {db_path}")
            except Exception as e:
                print(f"删除 {db_path} 失败: {e}")
        else:
            print(f"文件不存在: {db_path}")

def clean_uploads():
    """清理上传文件，但保留目录结构"""
    print("\n正在清理上传文件...")
    for upload_dir in UPLOAD_DIRS:
        if os.path.exists(upload_dir):
            try:
                # 获取目录中的所有文件（不包括子目录）
                files = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))]
                for file in files:
                    file_path = os.path.join(upload_dir, file)
                    os.remove(file_path)
                    print(f"已删除: {file_path}")
                print(f"已清理目录: {upload_dir}")
            except Exception as e:
                print(f"清理 {upload_dir} 失败: {e}")
        else:
            print(f"目录不存在: {upload_dir}")

def ensure_directories():
    """确保必要的目录存在"""
    print("\n确保必要的目录存在...")
    for upload_dir in UPLOAD_DIRS:
        if not os.path.exists(upload_dir):
            try:
                os.makedirs(upload_dir)
                print(f"已创建目录: {upload_dir}")
            except Exception as e:
                print(f"创建 {upload_dir} 失败: {e}")

def main():
    """主函数"""
    print("开始清理应用数据...")
    
    # 首先清理数据库
    clean_databases()
    
    # 然后清理上传文件
    clean_uploads()
    
    # 确保必要的目录存在
    ensure_directories()
    
    print("\n清理完成！应用已准备好部署。")

if __name__ == "__main__":
    main()

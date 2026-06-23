@echo off
REM ==============================================================
REM  VulnGuard 단일 실행파일(.exe) 빌드 스크립트 (Windows 전용)
REM  실행: 이 파일을 더블클릭하거나, 명령창에서  build_exe.bat
REM  결과:  dist\VulnGuard.exe  (USB에 복사해서 더블클릭으로 실행)
REM ==============================================================

echo [1/2] PyInstaller 설치 확인...
python -m pip install --quiet --upgrade pyinstaller
if errorlevel 1 (
    echo PyInstaller 설치 실패. Python 과 인터넷 연결을 확인하세요.
    pause
    exit /b 1
)

echo [2/2] 실행파일 빌드 중... (1~2분 소요)
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name VulnGuard ^
    --collect-submodules vulnguard ^
    run_gui.py

if errorlevel 1 (
    echo 빌드 실패.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  완료!  dist\VulnGuard.exe 가 생성되었습니다.
echo  이 파일 하나만 USB에 복사하면 어느 Windows PC에서나
echo  더블클릭으로 실행됩니다 (설치/파이썬 불필요).
echo ============================================================
pause

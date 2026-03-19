import React from 'react';
import api from '../api'; // หรือ baseURL ของคุณ

const DownloadPage = () => {

  const handleDownloadWindows = () => {
    // ให้ชี้ไปที่ /api/download/windows
    window.location.href = `${api.defaults.baseURL}/api/download/windows`;
  };

  const handleDownloadAndroid = () => {
    // ให้ชี้ไปที่ /api/download/android
    window.location.href = `${api.defaults.baseURL}/api/download/android`;
  };

  return (
    <div className="download-container">
      <h2>ดาวน์โหลดแอปพลิเคชัน</h2>
      
      <div className="download-options">
        <button onClick={handleDownloadWindows} className="btn">
          ดาวน์โหลดสำหรับ Windows (.exe)
        </button>

        <button onClick={handleDownloadAndroid} className="btn outline">
          ดาวน์โหลดสำหรับ Android (.apk)
        </button>
      </div>
    </div>
  );
};

export default DownloadPage;
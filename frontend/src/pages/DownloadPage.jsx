import React, { useEffect, useState } from 'react';
import api from '../api';

const DownloadPage = () => {
  const [items, setItems] = useState([]);
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.get('/api/download');
        setItems(res.data || []);
      } catch (err) {
        setMsg(err.response?.data?.error || 'Failed to load downloads');
      }
    };
    load();
  }, []);

  return (
    <>
      <h2>Download</h2>
      <p className="muted">
        เลือกดาวน์โหลดเวอร์ชันที่คุณต้องการด้านล่าง
      </p>

      {msg && (
        <p className="muted" style={{ color: 'var(--acc-1)' }}>
          {msg}
        </p>
      )}

      <div
        className="download-list"
        style={{
          display: 'grid',
          gap: '1rem',
          marginTop: '1rem'
        }}
      >
        {items.map((d) => (
          <div
            key={d.id}
            className="download-card"
            style={{
              padding: '1rem',
              borderRadius: '0.5rem',
              border: '1px solid var(--border, #ddd)'
            }}
          >
            <h3>{d.title || 'File'}</h3>
            {d.description && (
              <p className="muted">{d.description}</p>
            )}
            <a
              href={d.file_url}
              className="btn"
              target="_blank"
              rel="noreferrer"
            >
              Download
            </a>
          </div>
        ))}
      </div>
    </>
  );
};

export default DownloadPage;

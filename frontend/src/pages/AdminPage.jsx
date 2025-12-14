import React, { useEffect, useState } from 'react';
import api from '../api';

const AdminPage = () => {
  const [users, setUsers] = useState([]);
  const [carousel, setCarousel] = useState([]);
  const [sectionName, setSectionName] = useState('welcome_header');
  const [sectionContent, setSectionContent] = useState('');
  const [newIndex, setNewIndex] = useState('');
  const [newTitle, setNewTitle] = useState('');
  const [newSubtitle, setNewSubtitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newImage, setNewImage] = useState(null);
  const [fileMap, setFileMap] = useState({});
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        // ProtectedRoute ตรวจ admin แล้ว แต่โหลด users / carousel สำหรับตาราง
        const usersRes = await api.get('/api/admin/users');
        setUsers(usersRes.data || []);

        const carouselRes = await api.get('/api/admin/carousel');
        setCarousel(carouselRes.data || []);
      } catch (err) {
        setMsg(
          err.response?.data?.error ||
            'Failed to load admin data'
        );
      }
    };
    load();
  }, []);

  // ---- Homepage content ----
  const handleHomeSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      const section = sectionName.trim();
      await api.put('/api/homepage', {
        section_name: section,
        content: sectionContent
      });
      setMsg(`Section "${section}" saved.`);
    } catch (err) {
      setMsg(
        err.response?.data?.error ||
          'Failed to save homepage section'
      );
    }
  };

  // ---- Users table ----
  const handleUserFieldChange = (id, field, value) => {
    setUsers((prev) =>
      prev.map((u) =>
        u.id === id ? { ...u, [field]: value } : u
      )
    );
  };

  const handleUserSave = async (id) => {
    setMsg(null);
    const u = users.find((x) => x.id === id);
    if (!u) return;
    try {
      await api.put(`/api/admin/users/${id}`, {
        username: u.username || '',
        email: u.email,
        role: u.role
      });
      setMsg('User saved.');
    } catch (err) {
      setMsg(
        err.response?.data?.error ||
          'Failed to save user'
      );
    }
  };

  // ---- Carousel admin ----
  const reloadCarousel = async () => {
    const res = await api.get('/api/admin/carousel');
    setCarousel(res.data || []);
    setFileMap({});
  };

  const handleNewCarouselSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      if (!newImage) {
        setMsg('Please choose an image');
        return;
      }
      const fd = new FormData();
      fd.append('itemIndex', newIndex || '0');
      fd.append('title', newTitle);
      fd.append('subtitle', newSubtitle);
      fd.append('description', newDescription);
      fd.append('image', newImage);

      await api.post('/api/admin/carousel', fd, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });

      setNewIndex('');
      setNewTitle('');
      setNewSubtitle('');
      setNewDescription('');
      setNewImage(null);

      await reloadCarousel();
      setMsg('Carousel item created.');
    } catch (err) {
      setMsg(
        err.response?.data?.error ||
          'Failed to create carousel item'
      );
    }
  };

  const handleCarouselFieldChange = (id, field, value) => {
    setCarousel((prev) =>
      prev.map((item) =>
        item.id === id ? { ...item, [field]: value } : item
      )
    );
  };

  const handleCarouselFileChange = (id, file) => {
    setFileMap((prev) => ({ ...prev, [id]: file }));
  };

  const handleCarouselSave = async (id) => {
    setMsg(null);
    const item = carousel.find((x) => x.id === id);
    if (!item) return;
    try {
      const fd = new FormData();
      fd.append('itemIndex', item.item_index ?? 0);
      fd.append('title', item.title || '');
      fd.append('subtitle', item.subtitle || '');
      fd.append('description', item.description || '');
      const file = fileMap[id];
      if (file) {
        fd.append('image', file);
      }

      const res = await api.put(
        `/api/admin/carousel/${id}`,
        fd,
        {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        }
      );

      setCarousel((prev) =>
        prev.map((x) =>
          x.id === id ? res.data : x
        )
      );
      setMsg('Carousel item saved.');
    } catch (err) {
      setMsg(
        err.response?.data?.error ||
          'Failed to save carousel item'
      );
    }
  };

  const handleCarouselDelete = async (id) => {
    if (
      !window.confirm('Delete this carousel item?')
    ) {
      return;
    }
    setMsg(null);
    try {
      await api.delete(`/api/admin/carousel/${id}`);
      setCarousel((prev) =>
        prev.filter((x) => x.id !== id)
      );
      setMsg('Carousel item deleted.');
    } catch (err) {
      setMsg(
        err.response?.data?.error ||
          'Failed to delete carousel item'
      );
    }
  };

  return (
    <>
      <h2>Admin Dashboard</h2>

      {/* SECTION: Homepage Content */}
      <section>
        <h3>Homepage Content</h3>
        <form
          id="homeForm"
          onSubmit={handleHomeSubmit}
        >
          <label>Section name</label>
          <input
            type="text"
            id="section"
            placeholder="welcome_header"
            required
            value={sectionName}
            onChange={(e) =>
              setSectionName(e.target.value)
            }
          />

          <label>Content</label>
          <textarea
            id="content"
            rows={3}
            value={sectionContent}
            onChange={(e) =>
              setSectionContent(e.target.value)
            }
          />

          <button className="btn" type="submit">
            Save section
          </button>
        </form>
      </section>

      {/* SECTION: Users */}
      <section>
        <h3>Users</h3>
        <table id="usersTable">
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td>
                  <input
                    value={u.username || ''}
                    onChange={(e) =>
                      handleUserFieldChange(
                        u.id,
                        'username',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    value={u.email}
                    onChange={(e) =>
                      handleUserFieldChange(
                        u.id,
                        'email',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <select
                    value={u.role}
                    onChange={(e) =>
                      handleUserFieldChange(
                        u.id,
                        'role',
                        e.target.value
                      )
                    }
                  >
                    <option value="user">
                      user
                    </option>
                    <option value="admin">
                      admin
                    </option>
                  </select>
                </td>
                <td>
                  <button
                    className="btn small"
                    type="button"
                    onClick={() =>
                      handleUserSave(u.id)
                    }
                  >
                    Save
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* SECTION: Carousel (รูปแบบ admin.html เดิม) */}
      <section>
        <h3>Carousel</h3>

        {/* ฟอร์มเพิ่ม item ใหม่ */}
        <form
          id="carouselForm"
          onSubmit={handleNewCarouselSubmit}
        >
          <label>Index</label>
          <input
            type="number"
            value={newIndex}
            onChange={(e) =>
              setNewIndex(e.target.value)
            }
          />

          <label>Title</label>
          <input
            type="text"
            value={newTitle}
            onChange={(e) =>
              setNewTitle(e.target.value)
            }
          />

          <label>Subtitle</label>
          <input
            type="text"
            value={newSubtitle}
            onChange={(e) =>
              setNewSubtitle(e.target.value)
            }
          />

          <label>Description</label>
          <textarea
            rows={3}
            value={newDescription}
            onChange={(e) =>
              setNewDescription(e.target.value)
            }
          />

          <label>Image</label>
          <input
            type="file"
            accept="image/png,image/jpeg,image/jpg,image/gif,image/webp"
            onChange={(e) =>
              setNewImage(
                e.target.files?.[0] || null
              )
            }
          />

          <button className="btn" type="submit">
            Add carousel item
          </button>
        </form>

        <div style={{ height: '1rem' }} />

        {/* ตารางแก้ไข items เดิม */}
        <table id="carouselTable">
          <thead>
            <tr>
              <th>ID</th>
              <th>Index</th>
              <th>Preview</th>
              <th>Title</th>
              <th>Subtitle</th>
              <th>Description</th>
              <th>New Image</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {carousel.map((item) => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td>
                  <input
                    type="number"
                    value={item.item_index ?? 0}
                    onChange={(e) =>
                      handleCarouselFieldChange(
                        item.id,
                        'item_index',
                        Number(e.target.value)
                      )
                    }
                  />
                </td>
                <td>
                  {item.image_dataurl && (
                    <img
                      src={item.image_dataurl}
                      alt={item.title || ''}
                      style={{
                        width: 80,
                        height: 50,
                        objectFit: 'cover'
                      }}
                    />
                  )}
                </td>
                <td>
                  <input
                    type="text"
                    value={item.title || ''}
                    onChange={(e) =>
                      handleCarouselFieldChange(
                        item.id,
                        'title',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    type="text"
                    value={item.subtitle || ''}
                    onChange={(e) =>
                      handleCarouselFieldChange(
                        item.id,
                        'subtitle',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <textarea
                    rows={2}
                    value={item.description || ''}
                    onChange={(e) =>
                      handleCarouselFieldChange(
                        item.id,
                        'description',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/jpg,image/gif,image/webp"
                    onChange={(e) =>
                      handleCarouselFileChange(
                        item.id,
                        e.target.files?.[0] || null
                      )
                    }
                  />
                </td>
                <td>
                  <button
                    className="btn small"
                    type="button"
                    onClick={() =>
                      handleCarouselSave(item.id)
                    }
                  >
                    Save
                  </button>
                  <button
                    className="btn small danger"
                    type="button"
                    onClick={() =>
                      handleCarouselDelete(item.id)
                    }
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {msg && (
        <p id="msg" className="muted">
          {msg}
        </p>
      )}
    </>
  );
};

export default AdminPage;

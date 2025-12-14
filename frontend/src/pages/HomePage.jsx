import React, { useEffect, useState } from 'react';
import api from '../api';

const HomePage = () => {
  const [me, setMe] = useState(null);
  const [content, setContent] = useState({});
  const [carousel, setCarousel] = useState([]);
  const [index, setIndex] = useState(0);
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [meRes, contentRes, carouselRes] = await Promise.all([
          api.get('/api/users/me'),
          api.get('/api/homepage'),
          api.get('/api/carousel')
        ]);

        if (cancelled) return;

        setMe(meRes.data || null);

        const map = {};
        (contentRes.data || []).forEach((c) => {
          map[c.section_name] = c.content;
        });
        setContent(map);

        setCarousel(carouselRes.data || []);
      } catch (err) {
        if (!cancelled) {
          setMsg(
            err.response?.data?.error ||
              'Failed to load home data'
          );
        }
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const hasCarousel = carousel && carousel.length > 0;
  const safeIndex = hasCarousel
    ? ((index % carousel.length) + carousel.length) % carousel.length
    : 0;
  const currentItem = hasCarousel ? carousel[safeIndex] : null;

  const go = (delta) => {
    if (!hasCarousel) return;
    setIndex((i) => i + delta);
  };

  const goto = (i) => {
    if (!hasCarousel) return;
    setIndex(i);
  };

  const welcomeHeader =
    content.welcome_header ||
    (me
      ? `Welcome, ${me.username || me.email}`
      : 'Welcome');
  const mainParagraph =
    content.main_paragraph ||
    'This is your dashboard.';

  return (
    <>
      {/* main ของ home.html เดิมอยู่ใน .container (Layout จัดให้แล้ว) */}

      {/* Carousel block แบบเดิม */}
      <div className="carousel" id="carousel">
        <div
          className="carousel-track"
          id="carousel-track"
          style={{
            transform: `translateX(-${safeIndex * 100}%)`
          }}
        >
          {hasCarousel ? (
            carousel.map((item) => (
              <div
                className="carousel-slide"
                key={item.id}
              >
                {item.image_dataurl ? (
                  <img
                    src={item.image_dataurl}
                    alt={item.title || 'Slide'}
                  />
                ) : (
                  <div className="muted">
                    No image
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className="carousel-slide">
              <div className="muted">
                No carousel items
              </div>
            </div>
          )}
        </div>

        <button
          className="carousel-prev"
          id="carousel-prev"
          aria-label="รูปก่อนหน้า"
          title="< รูปก่อนหน้า"
          type="button"
          onClick={() => go(-1)}
          disabled={!hasCarousel || carousel.length <= 1}
        >
          &lt;
        </button>

        <button
          className="carousel-next"
          id="carousel-next"
          aria-label="รูปถัดไป"
          title="> รูปถัดไป"
          type="button"
          onClick={() => go(1)}
          disabled={!hasCarousel || carousel.length <= 1}
        >
          &gt;
        </button>

        <div
          className="carousel-indicators"
          id="carousel-indicators"
        >
          {hasCarousel &&
            carousel.map((item, i) => (
              <button
                key={item.id}
                type="button"
                className={i === safeIndex ? 'active' : ''}
                onClick={() => goto(i)}
              >
                {item.image_dataurl && (
                  <img
                    src={item.image_dataurl}
                    alt={item.title || `Slide ${i + 1}`}
                  />
                )}
              </button>
            ))}
        </div>
      </div>

      {/* กล่อง caption ใต้ carousel ตามต้นฉบับ */}
      <div
        id="carousel-caption-box"
        className="card"
      >
        <h3 id="cc-title">
          {currentItem?.title || ''}
        </h3>
        <h5
          id="cc-subtitle"
          className="muted"
        >
          {currentItem?.subtitle || ''}
        </h5>
        <p id="cc-desc">
          {currentItem?.description || ''}
        </p>
      </div>

      <hr />

      <h2 id="welcome_header">{welcomeHeader}</h2>
      <p id="main_paragraph">{mainParagraph}</p>

      {msg && (
        <p
          className="muted"
          style={{ color: 'var(--acc-1)' }}
        >
          {msg}
        </p>
      )}
    </>
  );
};

export default HomePage;

// backend/models/carousel.js
// IMPORTANT: do not access DB directly. Use pure-api only.

const { get, post } = require('../utils/pureApiClient');

async function getCarouselItems() {
  return get('/api/internal/carousel/items');
}

async function addCarouselItem(item) {
  return post('/api/internal/carousel/items/add', item);
}

async function updateCarouselItem(id, item) {
  return post('/api/internal/carousel/items/update', { id, ...item });
}

async function deleteCarouselItem(id) {
  return post('/api/internal/carousel/items/delete', { id });
}

module.exports = {
  getCarouselItems,
  addCarouselItem,
  updateCarouselItem,
  deleteCarouselItem,
};

const extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'];
module.exports = loc => extensions.some(ext => loc.toLowerCase().endsWith(ext));

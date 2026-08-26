// Service Worker för Toosome push-notifikationer
self.addEventListener('push', event => {
  if(!event.data) return;
  const data = event.data.json();
  const options = {
    body: data.body || 'En spelare söker match!',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    vibrate: [200, 100, 200],
    data: { url: data.url || 'https://toosome.com' },
    actions: [
      { action: 'open', title: '⚽ Spela nu!' }
    ]
  };
  event.waitUntil(
    self.registration.showNotification(data.title || 'Toosome', options)
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url
    ? event.notification.data.url
    : 'https://toosome.com';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      // Om appen redan är öppen — fokusera den
      for(const client of clientList){
        if(client.url.includes('toosome.com') && 'focus' in client){
          return client.focus();
        }
      }
      // Annars öppna ny flik
      if(clients.openWindow) return clients.openWindow(url);
    })
  );
});

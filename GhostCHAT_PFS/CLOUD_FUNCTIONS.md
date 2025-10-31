# Cloud Functions: TTL очистка сообщений (30 минут)

Используйте функцию ниже, чтобы серверно удалять сообщения старше 30 минут.

```js
const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

exports.pruneOld = functions.pubsub.schedule('every 15 minutes').onRun(async () => {
  const cutoff = Date.now() - 30*60*1000;
  const root = admin.database().ref();
  const roomsSnap = await root.child('rooms').once('value');
  const updates = {};
  roomsSnap.forEach(roomSnap => {
    const roomId = roomSnap.key;
    const msgs = roomSnap.child('messages');
    msgs.forEach(mSnap => {
      const m = mSnap.val();
      const ts = (typeof m.ts === 'number') ? m.ts : 0;
      if(ts && ts < cutoff){ updates[`rooms/${roomId}/messages/${mSnap.key}`] = null; }
    });
  });
  if(Object.keys(updates).length) await root.update(updates);
  return null;
});
```


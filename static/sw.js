// Cutlet PWA Service Worker
const CACHE_NAME = 'cutlet-v1.0.0';
const STATIC_CACHE = 'cutlet-static-v1.0.0';
const DYNAMIC_CACHE = 'cutlet-dynamic-v1.0.0';

// 캐시할 정적 파일들 (동적 페이지 '/'는 제외)
const STATIC_FILES = [
    '/static/icons/icon-192x192.png',
    '/static/icons/icon-512x512.png',
    '/static/icons/shortcut-96x96.png',
    '/manifest.json'
];

// 설치 시 정적 파일들을 캐시
self.addEventListener('install', (event) => {
    console.log('🔧 Cutlet Service Worker 설치 중...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then((cache) => {
                console.log('📦 정적 파일 캐싱 중...');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('✅ 정적 파일 캐싱 완료');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('❌ 정적 파일 캐싱 실패:', error);
            })
    );
});

// 활성화 시 이전 캐시 정리
self.addEventListener('activate', (event) => {
    console.log('🚀 Cutlet Service Worker 활성화 중...');
    
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('🗑️ 이전 캐시 삭제:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('✅ 이전 캐시 정리 완료');
                return self.clients.claim();
            })
    );
});

// 네트워크 요청 가로채기
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);

    // 1) HTML 문서는 항상 네트워크 우선 (세션 기반 동적 컨텐츠 보장)
    if (request.destination === 'document') {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    // 성공하면 동적 캐시에 저장
                    if (response.status === 200 && request.method === 'GET') {
                        const responseClone = response.clone();
                        caches.open(DYNAMIC_CACHE).then((cache) => cache.put(request, responseClone));
                    }
                    return response;
                })
                .catch(() => {
                    // 네트워크 실패 시 캐시된 페이지 또는 오프라인 페이지 반환
                    return caches.match(request).then((cached) => cached || caches.match('/offline.html'));
                })
        );
        return;
    }

    // 2) 정적 파일은 캐시 우선
    if (STATIC_FILES.includes(url.pathname)) {
        event.respondWith(
            caches.match(request).then((response) => {
                if (response) {
                    return response;
                }
                return fetch(request).then((netRes) => {
                    if (netRes.status === 200) {
                        const clone = netRes.clone();
                        caches.open(STATIC_CACHE).then((cache) => cache.put(request, clone));
                    }
                    return netRes;
                });
            })
        );
        return;
    }

    // 3) API는 네트워크 우선
    if (url.pathname.startsWith('/shorten') || url.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(request).catch(() => caches.match('/offline.html'))
        );
        return;
    }

    // 4) 그 외 요청은 기존 네트워크 우선
    event.respondWith(
        fetch(request)
            .then((response) => {
                if (response.status === 200 && request.method === 'GET') {
                    const responseClone = response.clone();
                    caches.open(DYNAMIC_CACHE).then((cache) => cache.put(request, responseClone));
                }
                return response;
            })
            .catch(() => caches.match(request))
    );
});

// 백그라운드 동기화 (선택사항)
self.addEventListener('sync', (event) => {
    if (event.tag === 'background-sync') {
        console.log('🔄 백그라운드 동기화 실행');
        event.waitUntil(doBackgroundSync());
    }
});

// 백그라운드 동기화 작업
async function doBackgroundSync() {
    try {
        // 오프라인 중 생성된 URL들을 동기화
        const offlineData = await getOfflineData();
        if (offlineData.length > 0) {
            console.log('📡 오프라인 데이터 동기화 중...');
            // 실제 동기화 로직 구현
        }
    } catch (error) {
        console.error('❌ 백그라운드 동기화 실패:', error);
    }
}

// 오프라인 데이터 가져오기
async function getOfflineData() {
    // IndexedDB나 localStorage에서 오프라인 데이터 조회
    return [];
}

// 푸시 알림 처리 (선택사항)
self.addEventListener('push', (event) => {
    if (event.data) {
        const data = event.data.json();
        const options = {
            body: data.body || '새로운 알림이 있습니다.',
            icon: '/static/icons/icon-192x192.png',
            badge: '/static/icons/shortcut-96x96.png',
            vibrate: [200, 100, 200],
            data: {
                url: data.url || '/'
            }
        };
        
        event.waitUntil(
            self.registration.showNotification('Cutlet', options)
        );
    }
});

// 알림 클릭 처리
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    event.waitUntil(
        clients.openWindow(event.notification.data.url)
    );
});

console.log('🔧 Cutlet Service Worker 로드 완료');

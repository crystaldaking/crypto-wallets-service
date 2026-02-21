# Roadmap

## Релиз 1.0.8 (Запланирован)

### Запланированные изменения

#### 1. Redis для кэширования
- Интеграция с Redis для кэширования:
  - Балансов кошельков
  - Производных адресов (миграция с LRU в памяти на Redis)
  - Истории транзакций (когда будет реализована)
  - Health check статуса
- Конфигурация подключения к Redis через переменные окружения
- TTL для разных типов данных

#### 2. Kubernetes Ready
- **Liveness probe**: `/api/v1/health/live` - проверка что сервис запущен
- **Readiness probe**: `/api/v1/health/ready` - проверка готовности принимать трафик (DB + Vault + Redis)
- **Startup probe**: для медленного старта (миграции, инициализация)
- Helm chart с конфигурацией:
  - Deployment с правильными probes
  - Service для HTTP и gRPC
  - ConfigMap для конфигурации
  - Secrets для чувствительных данных
  - HorizontalPodAutoscaler (HPA)

#### 3. Health Check Details
- Расширенный health check с детальной информацией:
  ```json
  {
    "status": "ok",
    "components": {
      "database": {
        "status": "ok",
        "latency_ms": 5,
        "connections": 5
      },
      "vault": {
        "status": "ok",
        "circuit_state": "closed",
        "latency_ms": 12
      },
      "redis": {
        "status": "ok",
        "latency_ms": 2
      }
    },
    "version": "1.0.8",
    "uptime_seconds": 3600
  }
  ```
- Отдельные эндпоинты:
  - `/api/v1/health/live` - liveness probe
  - `/api/v1/health/ready` - readiness probe
  - `/api/v1/health` - полный health check

#### 4. Обновление зависимостей
- **alloy**: 0.1 → 0.5+ (критично, много breaking changes)
- **axum**: 0.7 → 0.8+
- **tonic**: 0.12 → 0.13+
- **sqlx**: 0.8 → 0.9+
- **tokio**: проверить совместимость
- Прочие зависимости до latest stable

### Критерии готовности
- [ ] Redis интегрирован и работает
- [ ] Kubernetes manifests и Helm chart созданы
- [ ] Health check endpoints реализованы
- [ ] Все зависимости обновлены
- [ ] Тесты проходят (50+ unit тестов)
- [ ] Интеграционные тесты с Redis
- [ ] Документация обновлена

---

## Релиз 1.1.0 (Future)

### Новый функционал
- Получение баланса кошельков (интеграция с RPC)
- Поддержка Bitcoin (BTC)
- Batch операции (создание кошельков, подпись)
- История транзакций

### Безопасность
- JWT аутентификация
- Rate limiting per wallet
- IP whitelist

### Наблюдаемость
- Distributed Tracing (Jaeger)
- Alerting (Slack/Telegram)

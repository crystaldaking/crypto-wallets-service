# Kubernetes Readiness Report

## Версия: 1.0.8
## Дата: 2026-02-21

---

## Резюме

Приложение **практически stateless** и **готово для Kubernetes** с минимальными ограничениями.

---

## Stateless Анализ

### ✅ Полностью Stateless

```
┌──────────────────────────────────────────────────────────────┐
│                      Kubernetes Pods                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   Pod 1     │  │   Pod 2     │  │   Pod N     │          │
│  │             │  │             │  │             │          │
│  │ • LRU Cache │  │ • LRU Cache │  │ • LRU Cache │          │
│  │   (local)   │  │   (local)   │  │   (local)   │          │
│  │             │  │             │  │             │          │
│  │ • Circuit   │  │ • Circuit   │  │ • Circuit   │          │
│  │   Breaker   │  │   Breaker   │  │   Breaker   │          │
│  │   (local)   │  │   (local)   │  │   (local)   │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
└─────────┼────────────────┼────────────────┼──────────────────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    ▼                      ▼                      ▼
┌─────────┐         ┌──────────┐          ┌──────────┐
│PostgreSQL│         │  Redis   │          │  Vault   │
│ (State) │         │ (Cache)  │          │ (Crypto) │
└─────────┘         └──────────┘          └──────────┘
```

### ⚠️ Локальное состояние (acceptable)

| Компонент | Тип | Влияние | Митигация |
|-----------|-----|---------|-----------|
| LRU Cache | Локальный | Cache miss при переключении на другой pod | Redis как shared cache layer |
| Circuit Breaker | Per-instance | Не консистентное состояние между pods | Приемлемо - каждый pod защищает себя |
| Rate Limiter | Per-instance | Лимит умножается на количество pods | Для строгих лимитов - Redis rate limiter |

---

## K8s Манифест (Production Ready)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crypto-wallets-service
  labels:
    app: crypto-wallets-service
    version: v1.0.8
spec:
  replicas: 3  # ✅ Можно масштабировать!
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: crypto-wallets-service
  template:
    metadata:
      labels:
        app: crypto-wallets-service
        version: v1.0.8
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          image: crypto-wallets-service:v1.0.8
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 3000
              protocol: TCP
            - name: grpc
              containerPort: 3001
              protocol: TCP
          
          # ✅ Liveness Probe - проверяет что процесс жив
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: http
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          
          # ✅ Readiness Probe - проверяет готовность принимать трафик
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: http
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 2
          
          # ✅ Graceful shutdown - 30 секунд
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-c", "sleep 5"]
          
          env:
            # Обязательные
            - name: APP__SERVER__API_KEY
              valueFrom:
                secretKeyRef:
                  name: wallet-service-secrets
                  key: api-key
            - name: APP__DATABASE__URL
              valueFrom:
                secretKeyRef:
                  name: wallet-service-secrets
                  key: database-url
            - name: APP__VAULT__ADDRESS
              value: "https://vault.internal:8200"
            - name: APP__VAULT__TOKEN
              valueFrom:
                secretKeyRef:
                  name: wallet-service-secrets
                  key: vault-token
            
            # Опционально - Redis для shared cache
            - name: APP__REDIS__URL
              value: "redis://redis-cluster:6379"
            - name: APP__REDIS__ENABLED
              value: "true"
            - name: APP__REDIS__TTL_SECS
              value: "3600"
            
            # Логирование
            - name: RUST_LOG
              value: "info,crypto_wallets_service=debug"
          
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "1000m"
      
      # ✅ Graceful shutdown timeout
      terminationGracePeriodSeconds: 35

---
apiVersion: v1
kind: Service
metadata:
  name: crypto-wallets-service
  labels:
    app: crypto-wallets-service
spec:
  type: ClusterIP
  ports:
    - name: http
      port: 80
      targetPort: 3000
      protocol: TCP
    - name: grpc
      port: 81
      targetPort: 3001
      protocol: TCP
  selector:
    app: crypto-wallets-service

---
# HPA для автомасштабирования
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: crypto-wallets-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: crypto-wallets-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
```

---

## Проверка Readiness

### 1. Проверка graceful shutdown
```bash
# Убедиться что при SIGTERM завершается за 30s
kubectl exec -it pod/wallet-xxx -- /bin/sh -c "kill -TERM 1"
```

### 2. Проверка stateless
```bash
# Масштабирование должно работать без потери данных
kubectl scale deployment crypto-wallets-service --replicas=5
kubectl scale deployment crypto-wallets-service --replicas=2
# Все запросы должны продолжать работать
```

### 3. Проверка probes
```bash
kubectl get pods -w
# STATUS должен быть Running
# RESTARTS должен быть 0
```

---

## ⚠️ Критические замечания для K8s

### 1. Миграции при старте

**Проблема:** Каждый pod запускает миграции при старте:
```rust
sqlx::migrate!("./migrations").run(&pool).await?;
```

**Риск:** При одновременном старте нескольких pods - конфликт блокировок или race condition.

**Решение:**
```yaml
# Option A: Init Container для миграций (один pod)
apiVersion: apps/v1
kind: Job
metadata:
  name: db-migrate
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: migrate
          image: crypto-wallets-service:v1.0.8
          command: ["./crypto-wallets-service", "migrate"]
          env:
            - name: APP__DATABASE__URL
              valueFrom:
                secretKeyRef:
                  name: wallet-service-secrets
                  key: database-url
---
# Option B: Helm pre-install hook
# Option C: Отдельный CI/CD шаг перед deployment
```

**Или изменить код:**
```rust
// Добавить флаг командной строки
if args.run_migrations {
    sqlx::migrate!("./migrations").run(&pool).await?;
}
```

### 2. Отсутствие K8s манифестов

Рекомендуется добавить в репозиторий:
```
k8s/
├── base/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   └── hpa.yaml
├── overlays/
│   ├── production/
│   │   └── kustomization.yaml
│   └── staging/
│       └── kustomization.yaml
└── README.md
```

---

## Ограничения и Рекомендации

### Текущие ограничения

1. **Rate Limiting не shared**
   - При 3 pods лимит 100/min фактически становится 300/min
   - Для строгих лимитов нужен Redis-based rate limiter

2. **Circuit Breaker не shared**
   - Один pod может иметь open circuit, другой closed
   - Приемлемо - это улучшает отказоустойчивость

3. **LRU Cache не shared**
   - Cache hit rate ниже чем мог бы быть
   - Redis компенсирует это для address cache

### Рекомендации для улучшения

1. **Добавить Redis Rate Limiter** (для строгих лимитов)
2. **Добавить Distributed Circuit Breaker** (опционально)
3. **Pod Disruption Budget** для zero-downtime deployments

---

## Заключение

✅ **Приложение готово для Kubernetes**

- Stateless архитектура
- Graceful shutdown
- Health probes
- Горизонтальное масштабирование
- Отказоустойчивость

**Рекомендуемая конфигурация:**
- Min replicas: 2 (для HA)
- Max replicas: 10
- Redis: enabled (для shared cache)
- HPA: по CPU 70%

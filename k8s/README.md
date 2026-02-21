# Kubernetes Deployment

## Структура

```
k8s/
├── base/              # Базовые манифесты
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── hpa.yaml
│   ├── pdb.yaml
│   └── kustomization.yaml
└── overlays/
    ├── production/    # Production конфигурация
    └── staging/       # Staging конфигурация
```

## Быстрый старт

### Staging
```bash
kubectl apply -k k8s/overlays/staging/
```

### Production
```bash
# Сначала создайте secrets
kubectl create namespace crypto-wallets-production
kubectl create secret generic wallet-service-secrets \
  --from-literal=api-key=$(openssl rand -base64 32) \
  --from-literal=database-url=postgres://... \
  --from-literal=vault-token=... \
  -n crypto-wallets-production

# Примените конфигурацию
kubectl apply -k k8s/overlays/production/
```

## Проверка

```bash
# Статус подов
kubectl get pods -n crypto-wallets-production

# Логи
kubectl logs -f deployment/crypto-wallets-service -n crypto-wallets-production

# Health checks
kubectl port-forward svc/crypto-wallets-service 3000:80 -n crypto-wallets-production
curl http://localhost:3000/api/v1/health/ready
```

## Масштабирование

```bash
# Ручное масштабирование
kubectl scale deployment crypto-wallets-service --replicas=10 -n crypto-wallets-production

# HPA статус
kubectl get hpa -n crypto-wallets-production
```

## Важно: Миграции

⚠️ Перед деплоем убедитесь что миграции выполнены:

```bash
# Опция 1: Запустить один pod с миграциями
kubectl run migrate --rm -i --restart=Never \
  --image=crypto-wallets-service:v1.0.8 \
  --env="APP__DATABASE_URL=..." \
  -- ./crypto-wallets-service migrate

# Опция 2: Использовать init container (рекомендуется)
```

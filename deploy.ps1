# Deploy script for PacketsProject on Minikube

Write-Host "Starting Minikube..." -ForegroundColor Cyan
minikube start

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start Minikube" -ForegroundColor Red
    exit 1
}

Write-Host "`nMinikube started successfully!" -ForegroundColor Green

# Deploy infrastructure first
Write-Host "`nDeploying Kafka..." -ForegroundColor Cyan
kubectl apply -f k8s/kafka-deployment.yaml
kubectl apply -f k8s/kafka-service.yaml

Write-Host "`nDeploying Elasticsearch..." -ForegroundColor Cyan
kubectl apply -f k8s/elasticsearch-deployment.yaml
kubectl apply -f k8s/elasticsearch-service.yaml

Write-Host "`nDeploying Prometheus..." -ForegroundColor Cyan
kubectl apply -f k8s/prometheus.yaml

Write-Host "`nDeploying Kibana..." -ForegroundColor Cyan
kubectl apply -f k8s/kibana-deployment.yaml

Write-Host "`nDeploying Redpanda Console..." -ForegroundColor Cyan
kubectl apply -f k8s/redpanda-console.yaml

# Wait for infrastructure to be ready
Write-Host "`nWaiting for infrastructure pods to be ready..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s 2>$null
kubectl wait --for=condition=ready pod -l app=elasticsearch --timeout=120s 2>$null

# Deploy application services
Write-Host "`nDeploying Producer..." -ForegroundColor Cyan
kubectl apply -f k8s/producer-deployment.yaml
kubectl apply -f k8s/producer-service.yaml

Write-Host "`nDeploying Consumer..." -ForegroundColor Cyan
kubectl apply -f k8s/consumer-deployment.yaml
kubectl apply -f k8s/consumer-service.yaml

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Deployment complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`nPod status:" -ForegroundColor Cyan
kubectl get pods

Write-Host "`nService URLs:" -ForegroundColor Cyan
Write-Host "  Kibana:           $(minikube service kibana --url 2>$null)" 
Write-Host "  Prometheus:       $(minikube service prometheus --url 2>$null)"
Write-Host "  Redpanda Console: $(minikube service redpanda-console --url 2>$null)"

Write-Host "`nTo access Elasticsearch: kubectl port-forward svc/elasticsearch 9200:9200" -ForegroundColor Yellow

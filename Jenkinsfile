pipeline {
  agent {
    kubernetes {
      yaml """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: python
    image: python:3.12-slim
    command: ["cat"]
    tty: true
  - name: docker
    image: docker:24.0.7-cli
    command: ["cat"]
    tty: true
    volumeMounts:
    - name: docker-sock
      mountPath: /var/run/docker.sock
  - name: kubectl
    image: bitnami/kubectl:1.29
    command: ["cat"]
    tty: true
  volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
"""
    }
  }

  options {
    timestamps()
  }

  triggers {
    cron('H H 1 * *')
  }

  parameters {
    booleanParam(name: 'PROMOTE_TO_HOUSE', defaultValue: true, description: 'Auto-merge slave -> house when threshold is met')
    string(name: 'PROMOTE_THRESHOLD', defaultValue: '3', description: 'Commit threshold for slave -> house promotion')
  }

  environment {
    REGISTRY = "${env.REGISTRY ?: 'ghcr.io'}"
    IMAGE_NAME = "${env.IMAGE_NAME ?: 'sebastined/anxextor'}"
    KUBE_NAMESPACE = "${env.KUBE_NAMESPACE ?: 'default'}"
    KUBE_CONTEXT = "${env.KUBE_CONTEXT ?: 'default'}"
    GIT_REMOTE_URL = "${env.GIT_REMOTE_URL ?: 'https://github.com/sebastined/anxextor.git'}"
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Test (slave)') {
      when {
        branch 'slave'
      }
      steps {
        container('python') {
          sh """
            python -m pip install --upgrade pip
            python -m pip install -r requirements.txt
            python -m pytest -q
          """
        }
      }
    }

    stage('Build Image (house)') {
      when {
        branch 'house'
      }
      steps {
        container('docker') {
          sh """
            echo "Building image ${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}" 
            docker build -t ${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} .
            docker tag ${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} ${REGISTRY}/${IMAGE_NAME}:latest
          """
        }
      }
    }

    stage('Push Image (house)') {
      when {
        branch 'house'
      }
      steps {
        container('docker') {
          withCredentials([usernamePassword(credentialsId: 'docker-registry', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
            sh """
              echo "$REG_PASS" | docker login ${REGISTRY} -u "$REG_USER" --password-stdin
              docker push ${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}
              docker push ${REGISTRY}/${IMAGE_NAME}:latest
            """
          }
        }
      }
    }

    stage('Deploy (house)') {
      when {
        branch 'house'
      }
      steps {
        container('kubectl') {
          withCredentials([file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')]) {
            sh """
              kubectl config use-context ${KUBE_CONTEXT}
              if [ -d k8s ]; then
                kubectl -n ${KUBE_NAMESPACE} apply -f k8s
              else
                echo "No k8s manifests found."
              fi
            """
          }
        }
      }
    }

    stage('Promote slave -> house') {
      when {
        allOf {
          branch 'slave'
          expression { return params.PROMOTE_TO_HOUSE }
        }
      }
      steps {
        withCredentials([usernamePassword(credentialsId: 'git-bot', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_TOKEN')]) {
          sh """
            git config user.email "ci-bot@local"
            git config user.name "ci-bot"
            git fetch origin house slave
            AHEAD=$(git rev-list --count origin/house..origin/slave)
            echo "Slave ahead by $AHEAD commits."
            if [ "$AHEAD" -lt "${PROMOTE_THRESHOLD}" ]; then
              echo "Threshold not met. Skipping promotion."
              exit 0
            fi
            git checkout house
            git pull origin house
            git merge --no-ff origin/slave -m "Promote slave -> house"
            git push https://${GIT_USER}:${GIT_TOKEN}@${GIT_REMOTE_URL#https://} house
          """
        }
      }
    }

    stage('Promote house -> master (monthly)') {
      when {
        allOf {
          branch 'house'
          triggeredBy 'TimerTrigger'
        }
      }
      steps {
        withCredentials([usernamePassword(credentialsId: 'git-bot', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_TOKEN')]) {
          sh """
            git config user.email "ci-bot@local"
            git config user.name "ci-bot"
            git fetch origin master house
            git checkout master
            git pull origin master
            git merge --no-ff origin/house -m "Promote house -> master"
            git push https://${GIT_USER}:${GIT_TOKEN}@${GIT_REMOTE_URL#https://} master
          """
        }
      }
    }
  }
}

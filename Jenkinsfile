pipeline {
    agent {
        label "master"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '7'))
        timestamps()
    }

    environment {
        DOCKER_IMAGE_NAME = "jenkins-flask-sample"
        DOCKER_REGISTRY = "registry.cn-hangzhou.aliyuncs.com"
    }

    stages {
        stage("Initialize") {
            steps {
                withCredentials([
                        string(credentialsId: 'JWT_TOKEN_SECRET', variable: 'JWT_TOKEN_SECRET'),
                ]) {
                }

            }
            post {
                failure {
                    echo "Check Credentials Failure, Please Check Credentials Config!"

                }
                success {
                    echo "Check Credentials Success!"
                }
            }
        }

        stage('Build Docker Image') {

            steps {
                script {
                    docker.build("${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}")
                }
            }
            post {
                failure {
                    echo "Build Docker Image Failure!"
                }
                success {
                    echo "Build Docker Image Success!"
                }
            }
        }

        stage('Test Docker Image') {
            steps {
                echo "Todo: Run Test In Docker"
            }
        }


        stage('Publish Docker Image') {
            steps {
                script {
                    docker.withRegistry("${env.DOCKER_REGISTRY}", 'DOCKER_REGISTRY_CREDENTIAL') {
                        def image = docker.image("${env.DOCKER_IMAGE_NAME}:${env.BUILD_ID}")
                        image.push()
                        image.push('latest')
                    }
                }
            }
        }
    }

}
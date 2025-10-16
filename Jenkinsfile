pipeline {
    agent any

    environment {
        AWS_CREDENTIALS_ID = "aws-credentials-for-scan"
        SSH_CREDENTIALS_ID = "aws-ssh-key-1"
    }

    parameters {
        string(name: 'AWS_REGION', defaultValue: 'ap-south-1', description: 'Enter the AWS region.')
        choice(name: 'OS_TYPE', choices: ['All', 'Centos', 'RHEL', 'Ubuntu', 'Amazon Linux', 'Rocky Linux'], description: 'Select the OS family.')
        choice(name: 'UBUNTU_VERSION', choices: ['N/A', '22.04', '24.04'], description: 'Select a version for Ubuntu.')
        choice(name: 'AMAZON_LINUX_VERSION', choices: ['N/A', '2', '2023'], description: 'Select a version for Amazon Linux.')
        choice(name: 'Centos', choices: ['N/A', 'customCentos7_6_1810', 'customCentos7_9_2009'], description: 'Select a version for Centos.')
        choice(name: 'ROCKY_LINUX_VERSION', choices: ['N/A', '8', '9'], description: 'Select a version for Rocky Linux.')
        text(name: 'EXCLUDE_IPS', defaultValue: '', description: 'Enter IPs to exclude, one per line.')
        string(name: 'NOTIFICATION_EMAIL', defaultValue: 'rajeevsunny05@gmail.com', description: 'Enter email to receive notifications.')
    }

    stages {
        stage('Verify Tools') {
            steps {
                echo "Verifying required command-line tools..."
                sh 'aws --version'
                sh 'zip --version'
            }
        }

        stage('Checkout Script from GitHub') {
            steps {
                echo "Cloning the script repository..."
                git url: 'https://github.com/rjsunny05/aws-openscap-compliance.git', branch: 'main'
            }
        }

        stage('Run OpenSCAP Scan') {
            steps {
                withCredentials([
                    [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: env.AWS_CREDENTIALS_ID]
                ]) {
                    withCredentials([
                        sshUserPrivateKey(credentialsId: env.SSH_CREDENTIALS_ID, keyFileVariable: 'TEMP_SSH_KEY_FILE_PATH')
                    ]) {
                        script {
                            sh 'chmod +x run_openscap_scan.sh'

                            // This block is simplified. It now passes all parameters as environment variables to the script.
                            echo "🚀 Triggering the scan script with all filters."
                            sh """
                                export AWS_DEFAULT_REGION='${params.AWS_REGION}'
                                export SSH_KEY_FROM_JENKINS='${TEMP_SSH_KEY_FILE_PATH}'
                                export OS_TYPE='${params.OS_TYPE}'
                                export UBUNTU_VERSION='${params.UBUNTU_VERSION}'
                                export AMAZON_LINUX_VERSION='${params.AMAZON_LINUX_VERSION}'
                                export ROCKY_LINUX_VERSION='${params.ROCKY_LINUX_VERSION}' # ADDED EXPORT - FIXED COMMENT
                                export EXCLUDE_IPS='${params.EXCLUDE_IPS}'

                                ./run_openscap_scan.sh
                            """
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'openscap_reports/**/*.html', allowEmptyArchive: true

            script {
                def reportCount = sh(script: 'find openscap_reports -type f -name "*.html" 2>/dev/null | wc -l', returnStdout: true).trim()
                if (reportCount.toInteger() > 0) {
                    echo "Found ${reportCount} reports. Zipping them into scan-reports.zip"
                    sh "cd openscap_reports && zip -r ../scan-reports.zip ."
                } else {
                    echo "No reports were generated, skipping zip creation."
                }
            }

            emailext(
                subject: "${currentBuild.result}: Jenkins Job '${env.JOB_NAME}' Build #${env.BUILD_NUMBER}",
                body: """<p>Build Details:</p>
                        <p>Project: ${env.JOB_NAME}</p>
                        <p>Build Number: ${env.BUILD_NUMBER}</p>
                        <p>Status: ${currentBuild.result}</p>
                        <p>Build URL: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        <p>Scan reports are attached as a zip file and archived in Jenkins.</p>""",
                to: params.NOTIFICATION_EMAIL,
                attachmentsPattern: 'scan-reports.zip'
            )

            cleanWs()
        }
    }
}

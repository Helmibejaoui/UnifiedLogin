import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';

// import * as sqs from 'aws-cdk-lib/aws-sqs';

export class UnifiedLoginStack extends cdk.Stack {

    public readonly userPool: cognito.UserPool;
    public readonly userPoolClient: cognito.UserPoolClient;
    public readonly identityPool: cognito.CfnIdentityPool;

    constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        this.userPool = new cognito.UserPool(this, 'UserPool', {
            userPoolName: 'MyAppUserPool',
            selfSignUpEnabled: true,
            signInAliases: {email: true},
            autoVerify: {email: true},
            standardAttributes: {
                email: {required: true, mutable: true},
                phoneNumber: {required: false}
            },
            passwordPolicy: {
                minLength: 8,
                requireLowercase: true,
                requireUppercase: true,
                requireDigits: true,
                requireSymbols: false,
            },
            accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
            removalPolicy: cdk.RemovalPolicy.DESTROY, // For dev only
        });

        // 2. App Client (Web/App)
        this.userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
            userPool: this.userPool,
            authFlows: {
                userPassword: true,
                userSrp: true,
            },
            oAuth: {
                flows: {
                    authorizationCodeGrant: true,
                    implicitCodeGrant: true,
                },
                scopes: [cognito.OAuthScope.EMAIL],
                callbackUrls: [
                    'http://localhost:3000/callback', // Local dev
                    'https://your-production-domain.com/callback'
                ],
                logoutUrls: [
                    'http://localhost:3000/logout',
                    'https://your-production-domain.com/logout'
                ]
            },
            generateSecret: false, // For web apps
            preventUserExistenceErrors: true,
        });

        new cognito.UserPoolDomain(this, 'Domain', {
            userPool: this.userPool,
            cognitoDomain: {
                domainPrefix: 'unifiedlogin', // ← Change this!
            },
        });

        // 3. Identity Pool (Federated Identities)
        this.identityPool = new cognito.CfnIdentityPool(this, 'IdentityPool', {
            identityPoolName: 'MyAppIdentityPool',
            allowUnauthenticatedIdentities: false,
            cognitoIdentityProviders: [{
                clientId: this.userPoolClient.userPoolClientId,
                providerName: this.userPool.userPoolProviderName,
            }],
        });

        // 4. IAM Roles for Identity Pool
        const authenticatedRole = new iam.Role(this, 'AuthenticatedRole', {
            assumedBy: new iam.FederatedPrincipal(
                'cognito-identity.amazonaws.com',
                {
                    StringEquals: {
                        'cognito-identity.amazonaws.com:aud': this.identityPool.ref
                    },
                    'ForAnyValue:StringLike': {
                        'cognito-identity.amazonaws.com:amr': 'authenticated'
                    },
                },
                'sts:AssumeRoleWithWebIdentity'
            ),
        });

        // Add policies to the authenticated role
        authenticatedRole.addToPolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['mobileanalytics:PutEvents', 'cognito-sync:*'],
            resources: ['*'],
        }));

        // Attach roles to Identity Pool
        new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoleAttachment', {
            identityPoolId: this.identityPool.ref,
            roles: {
                authenticated: authenticatedRole.roleArn,
            },
        });

        // 5. Outputs
        new cdk.CfnOutput(this, 'UserPoolId', {value: this.userPool.userPoolId});
        new cdk.CfnOutput(this, 'UserPoolClientId', {
            value: this.userPoolClient.userPoolClientId
        });
        new cdk.CfnOutput(this, 'IdentityPoolId', {
            value: this.identityPool.ref
        });
        new cdk.CfnOutput(this, 'Region', {
            value: this.region
        });
    }
}

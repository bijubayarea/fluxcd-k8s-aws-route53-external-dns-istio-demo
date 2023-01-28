# Usage
terraform -chdir=terraform_eks_flux_install init
terraform -chdir=terraform_eks_flux_install apply

# Verify fluxcd

kubectl get gitrepositories.source.toolkit.fluxcd.io
kubectl get kustomizations.kustomize.toolkit.fluxcd.io

```
bijujoseph@XWHYXCD9JV fluxcd-k8s-aws-route53-external-dns-istio-demo % k get pods -n flux-system
NAME                                       READY   STATUS    RESTARTS      AGE
helm-controller-68c6c64796-rjbg2           1/1     Running   0             66m
kustomize-controller-fb98769c8-2mq86       1/1     Running   1 (66m ago)   66m
notification-controller-66b5c67b7d-9pz7b   1/1     Running   0             66m
source-controller-5c78b9749f-xhwnr         1/1     Running   0             66m

```


```

```


```
bijujoseph@XWHYXCD9JV fluxcd-k8s-aws-route53-external-dns-istio-demo % kubectl get gitrepositories.source.toolkit.fluxcd.io -A
NAMESPACE     NAME          URL                                                               AGE   READY   STATUS
flux-system   flux-system   ssh://git@github.com/bijubayarea-fluxcd/fluxcd-tenant-infra.git   85m   True    stored artifact for revision 'main/35b72ae2932a0f713d315cc0e9414f065d0ed873'

```

# argocd-k8s-aws-route53-external-dns-ingress-tls

ExternalDNS allows you to control DNS records dynamically via Kubernetes resources in a DNS provider-agnostic way

One great way to expose Kubernetes Applications to the world is using Ingress resources. On EKS we can avoid creating one Load Balancer each time we expose an Application. Moreover, K8S Ingress offers a single entry point to the cluster. So we can save money, manage and monitor one Load Balancer and reduce the attack surface of the Cluster. This is great, however, every time we need to expose an application we will need to create and manage DNS records manually. We can set externalDNS by adding a simple annotation to our ingress resources pointing to the DNS record and then it will be created automatically on Route53. In conclusion, using Ingress resources and ExternalDNS allows us to save time, money and improve security.

Normally when we expose an application on EKS we use a LoadBalancer service to expose the application, the problem with this is every time we create a new LoadBalancer service, AWS will create a new ELB. Ingress controllers on EKS allow us to use one ELB and configure the application access using Kubernetes resources.

By default an ingress controller doesn’t come with EKS, we need to install it. We’ll use nginx-ingress ingress controller to do that.

The NGINX Ingress Controller can be more efficient and cost-effective than a load balancer. Furthermore, features like path-based routing can be added with the NGINX ingress controller.

On the other hand, we can configure the Ingress controller as the only access to our Kubernetes Applications

With the Ingress controller we have the power to expose our applications to the world, however, creating each time every DNS record it’s annoying. To improve that we can use an external DNS to manage the DNS records of our ingresses automatically.

ExternalDNS synchronizes exposed Kubernetes Services and Ingresses with DNS providers. In a broader sense, ExternalDNS allows you to control DNS records dynamically via Kubernetes resources in a DNS provider-agnostic way.

## Pre-setup - Deploy k8s Infra

- [Deploy S3 backend for terraform state](https://github.com/bijubayarea/test-terraform-s3-remote-state)
- [Deploy EKS Cluster with 4 SPOT instances](https://github.com/bijubayarea/test-terraform-eks-cluster)
- Own the domain name (*.bijubayarea.tk) and update Internet domain registrar(like godaddy) with AWS nameservers 

## Steps
- Pre-setup steps above completed
- terraform to create k8s ServiceAccount to access Route53
- Deploy argoCD to EKS cluster
- Deploy ArgoCD App-set (boot-strap-app-set) for Ingress-Controller for host/path based routing
- Deploy ArgoCD App-set (boot-strap-app-set) for cert-manager to manage TLS certificates
- Deploy ArgoCD App-set (boot-strap-app-set) for external-dns to manipulate Route53
- Deploy ArgoCD App-set (test-app-set) to deploy applications - website, echo1 & echo2

## Final Goal
![Install external-dns](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/external_dns.png)
![Install external-dns](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/external_dns_2.png)
![install certmanager, ingress](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/ingress-tls.png)

## ** VERY IMPORTANT **
** VERY IMPORTANT **
** VERY IMPORTANT **
- argoCD app-set (boot-strap) auto synch should disabled
- First sych "ingress-nginx" app, wait 2 mins
- wait for ingress-controller's load balanacer to come up and check browser access to LB (`k get svc -n ingress-nginx ingress-nginx-controller`)
- update AWS Route53 A record "website.bijubayarea.tk" with ingress-controller's load balanacer
- synch "cert-manager"
- synch "external-dns"

cert-manger should be brought up only after nginx-ingress controller.

## terraform to create k8s ServiceAccount to access Route53

In the step, terraform is used to create 

- IAM Roles with trusted entity of EKS cluster's IODC provider
- IAM Policy to manipulate Route53 record
- IAM role-policy attachment to attach roles/policy
- Kubernetes service account to assume IAM role

```
terraform -chdir=./terraform-aws-route53/ init
terraform -chdir=./terraform-aws-route53/ plan
terraform -chdir=./terraform-aws-route53/ apply -auto-approve
```

## Deploy argoCD

Install Argo CD
All those components could be installed using a manifest provided by the Argo Project:
```
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.7/manifests/install.yaml

```

IF NEEDED Install Argo CD CLI
To interact with the API Server we need to deploy the CLI:
```
sudo curl --silent --location -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/download/v2.4.7/argocd-linux-amd64

sudochmod +x /usr/local/bin/argocd

```

Expose argocd-server
By default argocd-server is not publicaly exposed.  we will use a Load Balancer to make it usable:

```
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "LoadBalancer"}}'
Wait about 2 minutes for the LoadBalancer creation

export ARGOCD_SERVER=`kubectl get svc argocd-server -n argocd -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'`

```

Login
The initial password is autogenerated with the pod name of the ArgoCD API server:

```
export ARGO_PWD=`kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}"| base64 -d`

Using admin as login and the autogenerated password:
argocd login $ARGOCD_SERVER --username admin --password $ARGO_PWD --insecure

You should get as an output:
'admin'logged insuccessfully
```

## Deploy ArgoCD App-set (`boot-strap-app-set`) for Ingress-Controller & cert-manager: 

boot-strap-apps from github repo : `repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git`

See app-set at `repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git/application-set/boot-strap-app-set/boot-strap-app-set.yaml`

This will install ingress-controller and cert-manager

```
 - git:
      repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git
      revision: HEAD
      directories:
      - path: application-sets/boot-strap-apps/*

```
Install the App-set either using following ARGO CLI or from  web interface from LB `(581f61c66fa5407d8e6d89c12c1e479-1081541614.us-west-2.elb.amazonaws.com)`

** VERY IMPORTANT **
** VERY IMPORTANT **
- argoCD app-set (boot-strap) auto synch should disabled
- First sych "ingress-nginx" app, wait 2 mins, 
- wait for ingress-controller's load balanacer  to come up and check browser access to LB (`k get svc -n ingress-nginx ingress-nginx-controller`)
- synch "external-dns", update AWS Route53 A record "website.bijubayarea.tk" with ingress-controller's load balanacer
- synch "cert-manager"

```

argocd app create boot-strap --project default --sync-policy auto --auto-prune --sync-option CreateNamespace=true \
     --repo https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git \
     --path ./argocd-application-set/boot-strap-app-set/  \
     --dest-server https://kubernetes.default.svc --dest-namespace argocd 


```

## CONFIGURING THE EXTERNAL DNS
In short, external DNS is a pod running in your EKS cluster which watches over all your ingresses. When it detects an ingress with a host specified, it automatically picks up the hostname as well as the endpoint and creates a record for that resource in Route53. If the host is changed or deleted, external DNS will reflect the change immediately in Route53.

The next steps are :

Configuring the permissions to give access to Route53
Deploying the External DNS. ExternalDNS reads the ingresses DNS hostnames (website.bijubayarea.tk, echo1.bijubayarea.tk & 
echo2.bijubayarea.tk) and creates an A record in hosted zone of AWS Route53.

STEPS inside terraform

Set up IAM permissions and deploy ExternalDNS
```
IAM Policy:

data "aws_iam_policy_document" "route53_policy" {
  statement {
    actions = [
      "route53:ChangeResourceRecordSets",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/*",
    ]
  }

  statement {
    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets"
    ]

    resources = [
      "*"
    ]
  }

}

resource "aws_iam_policy" "policy" {

  name   = "${var.cluster}-${local.serviceaccount}-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.route53_policy.json
}

```

IAM Role: with trusted entity=EKS cluster OIDC
```
data "aws_iam_policy_document" "role" {

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${var.issuer_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${local.serviceaccount}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.issuer_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      # OIDC Provider ARN is the principal
      identifiers = ["${var.issuer_arn}"]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "role" {

  assume_role_policy = data.aws_iam_policy_document.role[0].json
  name               = "${var.cluster}-${local.serviceaccount}-role"
}

```

Attach IAM Policy to IAM Role
```
resource "aws_iam_role_policy_attachment" "attach" {

  policy_arn = aws_iam_policy.policy[0].arn
  role       = aws_iam_role.role[0].name
}
```

Create Kubernetes Service Account with above IAM Role to access Route53
```
resource "kubernetes_service_account" "sa" {
  depends_on = [kubernetes_namespace.ns]
  automount_service_account_token = true

  metadata {
    name      = local.serviceaccount
    namespace = var.namespace

    annotations = {
      "eks.amazonaws.com/role-arn" = "${var.iam_role}"
    }
  }

  lifecycle {
    ignore_changes = [
      metadata[0].labels,
    ]
  }
}
```

```
Synch argoCd app-set "external-dns"
This creates cluster-role to watch ingress for hostnames

```


##  DNS record for http-echo and website is auto managed



```
curl echo1.bijubayarea.tk

Output
echo1
```
![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/echo_1_image.png)

![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/echo_2_image.png)




## Deploy ArgoCD App-set (`httpecho-app-set`) for test http-echo: 

See app-set at `repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git/application-set/boot-strap-app-set/boot-strap-app-set.yaml`

This will install 2 deployments echo1 and echo2. Please see `https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/application-set/test-apps/http-echo`

```
 - git:
      repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git
      revision: HEAD
      directories:
      - path: application-sets/test-apps/*

```
Install the App-set either using following ARGO CLI or from  web interface 
from LB `(581f61c66fa5407d8e6d89c12c1e479-1081541614.us-west-2.elb.amazonaws.com)`
App-set provisions : namespace, deployment, service and ingress

```

 argocd app create test-apps --project default --sync-policy auto --auto-prune --sync-option CreateNamespace=true \
      --repo https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git \
      --path ./argocd-application-set/test-app-set/  \
      --dest-server https://kubernetes.default.svc --dest-namespace argocd 

```

 ArgoCD UI display

 ![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/argocd_snapshot.png)



## Installing and Configuring Cert-Manager
 install v1.7.1 of cert-manager into our cluster. cert-manager is a Kubernetes add-on that provisions TLS certificates from Let’s Encrypt and other certificate authorities (CAs) and manages their lifecycles. Certificates can be automatically requested and configured by annotating Ingress Resources, appending a tls section to the Ingress spec, and configuring one or more Issuers or ClusterIssuers to specify your preferred certificate authority. To learn more about Issuer and ClusterIssuer objects, consult the official cert-manager documentation on [Issuers](https://cert-manager.io/docs/concepts/issuer/).

Install cert-manager and its [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) (CRDs) like Issuers and ClusterIssuers by following the official [installation instructions](https://cert-manager.io/docs/installation/kubernetes/). Note that a namespace called cert-manager will be created into which the cert-manager objects will be created:

ArgoCD will deploy the cert-manager in namespace=cert-manager

```
Add yaml files under 
application-set/boot-strap-apps/cert-manager/cert-manager.yaml
application-set/boot-strap-apps/cert-manager/cluster-issuer-prod-cert.yaml

```


Add annotate ingress=httpecho-ingress with ClusterIssuer just created - `cert-manager.io/cluster-issuer: "letsencrypt-prod"`.
"letsencrypt-prod" is the ClusterIssuer.

Here we add an annotation to set the cert-manager ClusterIssuer to `letsencrypt-prod`, the test certificate ClusterIssuer. We also add an annotation that describes the type of ingress, in this case nginx.


Add tls to ingress=httpecho-ingress
We also add a tls block to specify the hosts for which we want to acquire certificates, and specify a secretName. This secret will contain the TLS private key and issued certificate. Be sure to swap out bijubayarea.tk with the domain for which you’ve created DNS records.

More details in [Securing Ingress Resources](https://cert-manager.io/docs/usage/ingress/)

- Securing Ingress Resources
  A common use-case for cert-manager is requesting TLS signed certificates to secure your ingress resources. This can be done by simply adding 
  annotations to your Ingress resources and cert-manager will facilitate creating the Certificate resource for you. A small sub-component of 
  cert-manager, ingress-shim, is responsible for this.

- How It Works
  The sub-component ingress-shim watches Ingress resources across your cluster. If it observes an Ingress with annotations described in the 
  Supported Annotations section, it will ensure a Certificate resource with the name provided in the tls.secretName field and configured as 
  described on the Ingress exists. For example:

```
metadata:
  name: echo-ingress
  namespace: http-echo
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: "letsencrypt-prod"


spec:
  tls:
  - hosts:
    - echo1.bijubayarea.tk
    - echo2.bijubayarea.tk
    secretName: http-echo-tls

```

##  Check certificates managed by Cert-Manager

```
$ kubectl -n http-echo describe ingress echo-ingress
Name:             echo-ingress
Labels:           app.kubernetes.io/instance=http-echo
Namespace:        http-echo
Address:          afd597bb1a7d54c099cee24475938458-1587408250.us-west-2.elb.amazonaws.com
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
TLS:
  http-echo-tls terminates echo1.bijubayarea.tk,echo2.bijubayarea.tk
Rules:
  Host                  Path  Backends
  ----                  ----  --------
  echo1.bijubayarea.tk
                        /   echo1:80 (10.0.1.117:5678)
  echo2.bijubayarea.tk
                        /   echo2:80 (10.0.2.101:5678)
Annotations:            cert-manager.io/cluster-issuer: letsencrypt-prod
                        kubernetes.io/ingress.class: nginx
Events:
  Type    Reason             Age                    From                      Message
  ----    ------             ----                   ----                      -------
  Normal  Sync               2m22s (x3 over 5h43m)  nginx-ingress-controller  Scheduled for sync
  Normal  CreateCertificate  2m22s                  cert-manager              Successfully created Certificate "http-echo-tls"


$ kubectl describe ingress -n http-echo
Name:             cm-acme-http-solver-mgc8d
Labels:           acme.cert-manager.io/http-domain=1312032652
                  acme.cert-manager.io/http-token=1280315029
                  acme.cert-manager.io/http01-solver=true
Namespace:        http-echo
Address:          afd597bb1a7d54c099cee24475938458-1587408250.us-west-2.elb.amazonaws.com
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host                  Path  Backends
  ----                  ----  --------
  echo2.bijubayarea.tk
                        /.well-known/acme-challenge/sw1nir1dCiTnUpAcDoqMNg3TMu1bDsQ7NOZj-DlgCk0   cm-acme-http-solver-fjphw:8089 (<none>)
Annotations:            kubernetes.io/ingress.class: nginx
                        nginx.ingress.kubernetes.io/whitelist-source-range: 0.0.0.0/0,::/0
Events:
  Type    Reason  Age              From                      Message
  ----    ------  ----             ----                      -------
  Normal  Sync    2s (x2 over 6s)  nginx-ingress-controller  Scheduled for sync


Name:             cm-acme-http-solver-zkvp5
Labels:           acme.cert-manager.io/http-domain=1310984075
                  acme.cert-manager.io/http-token=1046154894
                  acme.cert-manager.io/http01-solver=true
Namespace:        http-echo
Address:          afd597bb1a7d54c099cee24475938458-1587408250.us-west-2.elb.amazonaws.com
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host                  Path  Backends
  ----                  ----  --------
  echo1.bijubayarea.tk
                        /.well-known/acme-challenge/kMjIh0z6E9NwmeeUBT2TKvP2Vz4iDzlcWaVa6Hb9lSk   cm-acme-http-solver-rztlw:8089 (10.0.3.26:8089)
Annotations:            kubernetes.io/ingress.class: nginx
                        nginx.ingress.kubernetes.io/whitelist-source-range: 0.0.0.0/0,::/0
Events:
  Type    Reason  Age              From                      Message
  ----    ------  ----             ----                      -------
  Normal  Sync    3s (x2 over 7s)  nginx-ingress-controller  Scheduled for sync


```

```
$ kubectl get certificates

$ kubectl describe certificates

$ k -n http-echo get certificates
NAME            READY   SECRET          AGE
http-echo-tls   True    http-echo-tls   2m37s


$ k -n http-echo describe  certificates http-echo-tls
Name:         http-echo-tls
Namespace:    http-echo
Labels:       app.kubernetes.io/instance=http-echo
Annotations:  <none>
API Version:  cert-manager.io/v1
Kind:         Certificate
Metadata:
  Creation Timestamp:  2022-10-30T19:38:33Z
  Generation:          1

    Manager:      controller
    Operation:    Update
    Subresource:  status
    Time:         2022-10-30T19:40:34Z
  Owner References:
    API Version:           networking.k8s.io/v1
    Block Owner Deletion:  true
    Controller:            true
    Kind:                  Ingress
    Name:                  echo-ingress
    UID:                   44860053-b2ad-481d-9614-a665c2541b1e
  Resource Version:        36730
  UID:                     2e9a72ec-4198-47ff-8689-b35ac5e85a02
Spec:
  Dns Names:
    echo1.bijubayarea.tk
    echo2.bijubayarea.tk
  Issuer Ref:
    Group:      cert-manager.io
    Kind:       ClusterIssuer
    Name:       letsencrypt-prod
  Secret Name:  http-echo-tls
  Usages:
    digital signature
    key encipherment
Status:
  Conditions:
    Last Transition Time:  2022-10-30T19:40:34Z
    Message:               Certificate is up to date and has not expired
    Observed Generation:   1
    Reason:                Ready
    Status:                True
    Type:                  Ready
  Not After:               2023-01-28T18:40:32Z
  Not Before:              2022-10-30T18:40:33Z
  Renewal Time:            2022-12-29T18:40:32Z
  Revision:                1
Events:
  Type    Reason     Age    From          Message
  ----    ------     ----   ----          -------
  Normal  Issuing    2m56s  cert-manager  Issuing certificate as Secret does not exist
  Normal  Generated  2m55s  cert-manager  Stored new private key in temporary Secret resource "http-echo-tls-bcshd"
  Normal  Requested  2m55s  cert-manager  Created new CertificateRequest resource "http-echo-tls-ztsgl"
  Normal  Issuing    55s    cert-manager  The certificate has been successfully issued


$ kubectl get orders

$ kubectl -n http-echo get orders
NAME                             STATE   AGE
http-echo-tls-ztsgl-2650895051   valid   3m51s


$ kubectl -n http-echo describe orders http-echo-tls-ztsgl-2650895051
Name:         http-echo-tls-ztsgl-2650895051
Namespace:    http-echo
Labels:       app.kubernetes.io/instance=http-echo
Annotations:  cert-manager.io/certificate-name: http-echo-tls
              cert-manager.io/certificate-revision: 1
              cert-manager.io/private-key-secret-name: http-echo-tls-bcshd
API Version:  acme.cert-manager.io/v1
Kind:         Order
Metadata:
  Creation Timestamp:  2022-10-30T19:38:34Z
  Generation:          1

    Manager:      controller
    Operation:    Update
    Subresource:  status
    Time:         2022-10-30T19:40:34Z
  Owner References:
    API Version:           cert-manager.io/v1
    Block Owner Deletion:  true
    Controller:            true
    Kind:                  CertificateRequest
    Name:                  http-echo-tls-ztsgl
    UID:                   5c8384a4-dbde-4f44-a5be-658900427ef3
  Resource Version:        36709
  UID:                     49abbc2b-053a-42a2-af0f-aaf43728eda4
Spec:
  Dns Names:
    echo1.bijubayarea.tk
    echo2.bijubayarea.tk
  Issuer Ref:
    Group:  cert-manager.io
    Kind:   ClusterIssuer
    Name:   letsencrypt-prod
  Request:  
Status:
  Authorizations:
    Challenges:
      Token:        qBdBScMWHuuMqfE11rFM9XF99-7nzHu1IJpUWTyurvo
      Type:         http-01
      URL:          https://acme-v02.api.letsencrypt.org/acme/chall-v3/170511270132/3pEBjA
      Token:        qBdBScMWHuuMqfE11rFM9XF99-7nzHu1IJpUWTyurvo
      Type:         dns-01
      URL:          https://acme-v02.api.letsencrypt.org/acme/chall-v3/170511270132/U7rydQ
      Token:        qBdBScMWHuuMqfE11rFM9XF99-7nzHu1IJpUWTyurvo
      Type:         tls-alpn-01
      URL:          https://acme-v02.api.letsencrypt.org/acme/chall-v3/170511270132/qmJBcw
    Identifier:     echo1.bijubayarea.tk
    Initial State:  pending
    URL:            https://acme-v02.api.letsencrypt.org/acme/authz-v3/170511270132
    Wildcard:       false
    Challenges:
      Token:        ZwoaayhcNDbBWYrPMltjjub6HHppovgZkGDh_i5CJJ4
      Type:         http-01
      URL:          https://acme-v02.api.letsencrypt.org/acme/chall-v3/170511270142/6RQ5Mg
    Identifier:     echo2.bijubayarea.tk
    Initial State:  valid
    URL:            https://acme-v02.api.letsencrypt.org/acme/authz-v3/170511270142
    Wildcard:       false
  Certificate:      
  Finalize URL:     https://acme-v02.api.letsencrypt.org/acme/finalize/801601932/139424283242
  State:            valid
  URL:              https://acme-v02.api.letsencrypt.org/acme/order/801601932/139424283242
Events:
  Type    Reason    Age    From          Message
  ----    ------    ----   ----          -------
  Normal  Created   4m26s  cert-manager  Created Challenge resource "http-echo-tls-ztsgl-2650895051-4074663538" for domain "echo1.bijubayarea.tk"
  Normal  Complete  2m28s  cert-manager  Order completed successfully


$  kubectl -n website get cert
NAME          READY   SECRET        AGE
website-tls   True    website-tls   5m33s


$ kubectl -n website get orders
NAME                           STATE   AGE
website-tls-fg25f-2139627901   valid   5m42s
```

## Results:

Browser verifies CA authority - letsencrypt
![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/http-echo-secure_connection.png)

![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/http-echo-secure_connection_2.png)

After adding a personal website in 
```
$ ls application-set/test-apps/website/
personal-website-deployment.yaml  
personal-website-ingress.yaml  
personal-website-namespace.yaml  
personal-website-service.yaml

https://https://website.bijubayarea.tk/

```
![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/personal_website_tls.png)

## Verify Route53 is AUTO updated with DNS entry

pod external-dns will auto add a DNS A record in hosted zone for the hostname defined in ingress
Check if the ELB load balancer names is correct in the entry for the DNS A Record

![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/Route53_config.png)

Logs of pod
```
$ k get pod -n external-dns
NAME                            READY   STATUS    RESTARTS   AGE
external-dns-5784c4bc77-s5dkf   1/1     Running   0          43s


$ k logs  -n external-dns external-dns-5784c4bc77-s5dkf
time="2022-10-30T18:41:00Z" level=info msg="config: {APIServerURL: KubeConfig: RequestTimeout:30s DefaultTargets:[] ContourLoadBalancerService:heptio-contour/contour GlooNamespace:gloo-system SkipperRouteGroupVersion:zalando.org/v1 Sources:[service ingress] Namespace: AnnotationFilter: LabelFilter: FQDNTemplate: CombineFQDNAndAnnotation:false IgnoreHostnameAnnotation:false IgnoreIngressTLSSpec:false IgnoreIngressRulesSpec:false Compatibility: PublishInternal:false PublishHostIP:false AlwaysPublishNotReadyAddresses:false ConnectorSourceServer:localhost:8080 Provider:aws GoogleProject: GoogleBatchChangeSize:1000 GoogleBatchChangeInterval:1s GoogleZoneVisibility: DomainFilter:[bijubayarea.tk] ExcludeDomains:[] RegexDomainFilter: RegexDomainExclusion: ZoneNameFilter:[] ZoneIDFilter:[] AlibabaCloudConfigFile:/etc/kubernetes/alibaba-cloud.json AlibabaCloudZoneType: AWSZoneType:public AWSZoneTagFilter:[] AWSAssumeRole: AWSBatchChangeSize:1000 AWSBatchChangeInterval:1s AWSEvaluateTargetHealth:true AWSAPIRetries:3 AWSPreferCNAME:false AWSZoneCacheDuration:0s AzureConfigFile:/etc/kubernetes/azure.json AzureResourceGroup: AzureSubscriptionID: AzureUserAssignedIdentityClientID: BluecatConfigFile:/etc/kubernetes/bluecat.json CloudflareProxied:false CloudflareZonesPerPage:50 CoreDNSPrefix:/skydns/ RcodezeroTXTEncrypt:false AkamaiServiceConsumerDomain: AkamaiClientToken: AkamaiClientSecret: AkamaiAccessToken: AkamaiEdgercPath: AkamaiEdgercSection: InfobloxGridHost: InfobloxWapiPort:443 InfobloxWapiUsername:admin InfobloxWapiPassword: InfobloxWapiVersion:2.3.1 InfobloxSSLVerify:true InfobloxView: InfobloxMaxResults:0 InfobloxFQDNRegEx: InfobloxCreatePTR:false DynCustomerName: DynUsername: DynPassword: DynMinTTLSeconds:0 OCIConfigFile:/etc/kubernetes/oci.yaml InMemoryZones:[] OVHEndpoint:ovh-eu OVHApiRateLimit:20 PDNSServer:http://localhost:8081 PDNSAPIKey: PDNSTLSEnabled:false TLSCA: TLSClientCert: TLSClientCertKey: Policy:upsert-only Registry:txt TXTOwnerID:us-west-2 TXTPrefix: TXTSuffix: Interval:1m0s MinEventSyncInterval:5s Once:false DryRun:false UpdateEvents:false LogFormat:text MetricsAddress::7979 LogLevel:info TXTCacheInterval:0s TXTWildcardReplacement: ExoscaleEndpoint:https://api.exoscale.ch/dns ExoscaleAPIKey: ExoscaleAPISecret: CRDSourceAPIVersion:externaldns.k8s.io/v1alpha1 CRDSourceKind:DNSEndpoint 
ServiceTypeFilter:[] CFAPIEndpoint: CFUsername: CFPassword: RFC2136Host: RFC2136Port:0 RFC2136Zone: RFC2136Insecure:false RFC2136GSSTSIG:false RFC2136KerberosRealm: RFC2136KerberosUsername: RFC2136KerberosPassword: RFC2136TSIGKeyName: RFC2136TSIGSecret: RFC2136TSIGSecretAlg: RFC2136TAXFR:false RFC2136MinTTL:0s RFC2136BatchChangeSize:50 NS1Endpoint: NS1IgnoreSSL:false NS1MinTTLSeconds:0 TransIPAccountName: TransIPPrivateKeyFile: DigitalOceanAPIPageSize:50 ManagedDNSRecordTypes:[A CNAME] GoDaddyAPIKey: GoDaddySecretKey: GoDaddyTTL:0 GoDaddyOTE:false OCPRouterName:}"
time="2022-10-30T18:41:00Z" level=info msg="Instantiating new Kubernetes client"
time="2022-10-30T18:41:00Z" level=info msg="Using inCluster-config based on serviceaccount-token"
time="2022-10-30T18:41:00Z" level=info msg="Created Kubernetes client https://172.20.0.1:443"
time="2022-10-30T18:41:06Z" level=info msg="Applying provider record filter for domains: [bijubayarea.tk. .bijubayarea.tk.]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo1.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo1.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo2.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo2.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE website.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE website.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="6 record(s) in zone bijubayarea.tk. [Id: /hostedzone/Z0401868YSGSUUY2AFTH] were successfully updated"
```

`A` record for DNS Hosts (echo1.bijubayarea.tk, echo2.bijubayarea.tk and website.bijubayarea.tk) updated with correct 
Load balancer of ingress controller. All incoming traffic for these DNS hostnames get routes to ingress controller

Check `A` Record has correct hostname and LB

```
$ k get svc -n ingress-nginx ingress-nginx-controller
NAME                       TYPE           CLUSTER-IP      EXTERNAL-IP                                                               PORT(S)                      AGE
ingress-nginx-controller   LoadBalancer   172.20.78.181   ae2461394216a4ccdaf93fa5676c6a9a-2128055302.us-west-2.elb.amazonaws.com   80:30838/TCP,443:30217/TCP   79m  
```

## Debug External DNS

 if any problem with the DNS records after 300 seconds or 5 minutes we could check the External DNS pod Logs.
 ```
k logs  -n external-dns external-dns-5784c4bc77-s5dkf

time="2022-10-30T18:41:00Z" level=info msg="Instantiating new Kubernetes client"
time="2022-10-30T18:41:00Z" level=info msg="Using inCluster-config based on serviceaccount-token"
time="2022-10-30T18:41:00Z" level=info msg="Created Kubernetes client https://172.20.0.1:443"
time="2022-10-30T18:41:06Z" level=info msg="Applying provider record filter for domains: [bijubayarea.tk. .bijubayarea.tk.]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo1.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo1.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo2.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE echo2.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE website.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="Desired change: CREATE website.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T18:41:06Z" level=info msg="6 record(s) in zone bijubayarea.tk. [Id: /hostedzone/Z0401868YSGSUUY2AFTH] were successfully updated"
 ```
## Conclusion

In this guide, you set up an Nginx Ingress to load balance and route external requests to backend Services, inside of your Kubernetes cluster. 
You also secured the Ingress by installing the cert-manager certificate provisioner and setting up a Let’s Encrypt certificate for three host paths(echo1, echo2 & website)

External DNS also takes cares of picking up any new hostnames from new Ingress and update `A` record of hostname in Route53 with new hostnames

## To delete argoCD app:

Use either argocd CLI or argoCd GUI to delete infra

```
argocd app delete test-apps
** Allow 5 mins for external-dns to delete A record from Route53 **
argocd app delete boot-strap
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "ClusterIP"}}'

kubectl delete -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.7/manifests/install.yaml
kubectl delete namespace argocd


```

```
terraform -chdir=./terraform-aws-route53/ apply -auto-approve
terraform destroy test-terraform-eks-cluster
terraform destroy test-terraform-s3-remote-state

```

## Route53 A record auto deleted

external-dns is set to policy [- --policy=sync ] instead of [--policy=upsert-only]
Please see file argocd-application-set/boot-strap-apps/external-dns/deployment-external-dns.yaml

So when the test-apps are deleted, the A records in Route53 is also auto deleted
```

$ k logs -n external-dns external-dns-5646459f84-kjzzt

time="2022-10-30T19:57:38Z" level=info msg="Instantiating new Kubernetes client"
time="2022-10-30T19:57:38Z" level=info msg="Using inCluster-config based on serviceaccount-token"
time="2022-10-30T19:57:38Z" level=info msg="Created Kubernetes client https://172.20.0.1:443"
time="2022-10-30T19:57:45Z" level=info msg="Applying provider record filter for domains: [bijubayarea.tk. .bijubayarea.tk.]"
time="2022-10-30T19:57:45Z" level=info msg="Desired change: DELETE echo1.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T19:57:45Z" level=info msg="Desired change: DELETE echo1.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T19:57:45Z" level=info msg="Desired change: DELETE echo2.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T19:57:45Z" level=info msg="Desired change: DELETE echo2.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T19:57:45Z" level=info msg="Desired change: DELETE website.bijubayarea.tk A [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T19:57:45Z" level=info msg="Desired change: DELETE website.bijubayarea.tk TXT [Id: /hostedzone/Z0401868YSGSUUY2AFTH]"
time="2022-10-30T19:57:45Z" level=info msg="6 record(s) in zone bijubayarea.tk. [Id: /hostedzone/Z0401868YSGSUUY2AFTH] were successfully updated"
```


![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/Route53_config_post_app_delete.png)
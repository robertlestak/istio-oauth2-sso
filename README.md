# Istio OAuth2 SSO

A small external API service and Istio `EnvoyFilter` to enable federated OAuth2 authentication / SSO for workloads running inside an Istio service mesh.

## Background

Istio natively supports `JWT` Validation at edge, however currently does not implement the full OIDC flow.

For applications which natively support OIDC an Istio `AuthorizationPolicy` can be used to validate the user's JWT at edge, however if the application does not handle the OIDC lifecycle / flow, Istio cannot natively redirect the user to the IDP, nor can it handle cross-application SSO cookies.

To enable OIDC auth on legacy applications or those which do not natively integrate with a federated IDP, this service and filter will enable Istio mesh operators to enforce an `AuthorizationPolicy` on workloads and handle the full OIDC lifecycle, regardless of the underlying application's support for OIDC.

As Google has stated that native OIDC integration is not on the Istio road map, and the solution developed by IBM relies on the now-deprecated Mixer, this solution aims to be a more generic, lighter weight, and pluggable implementation of OAuth2 using currently-supported native Istio resources and constructs.

## Architecture

This solution relies heavily on native Istio resources as defined in Istio 1.6. 

As the Istio API moves quickly, you may need to make changes to the code to suit your specific Istio environment.

<img src="./docs/architecture/istio-oauth2.png" width="700px">

## Alternatives

This is one option of implementing SSO / federated authx in Istio, but is not the only solution.

Salmaan Rashid has a [great write up](https://medium.com/google-cloud/external-authorization-server-with-istio-1159b21682bb) about using an external authentication server pathched into envoy at the ingress gateway to provide a very similar experience.

Google has also suggested the use of [Identity Aware Proxy](https://cloud.google.com/iap/docs/concepts-overview) as a layer above the Istio ingress gateway, however the native Istio and envoy implementation was chosen here for vendor agnosticism and a more native Istio approach.

Google also raised the option of using `envoy-wasm` to provide the required capability entirely within the envoy filter. At the time of writing this, `envoy-wasm` is not merged back into upstream `envoy` and would therefore require building from source and patching all istio clusters to use a custom `envoy-wasm` image. This will probably be a moot point in a few weeks when `envoy-wasm` support is merged to upstream.

However the Lua filter + external API server approach was chosen over `envoy-wasm` to reduce the overhead and latency of the envoy proxy on every request. 

By shifting all of the OAuth logic to a separate scalable service, the envoy lua filter to handle token and redirect logic can remain lean, and the "heavy lifting" of the OAuth process can live independent of envoy.

[This GitHub issue](https://github.com/istio/istio/issues/8619) contains great discussion on this topic and includes a Lua example that is the basis for the Lua envoy filter in this implementation.

## Usage

### Build

```
# build image
docker build . -t docker-registry.example.com/istio-oauth2:latest
# push to registry
docker push docker-registry.example.com/istio-oauth2:latest
```

### Configure

#### State Management

When a user is redirected to the IDP, their redirect URL, IDP ClientID, and token must be stored in state during the handshake and redirect process.

The session store is configurable with `SESSION_STORE_TYPE`.

The default session state store is `cookie`. This will store the state on the client device as an encrypted cookie. This has the benefit of not requiring any additional resources, and is completely stateless from the service scalability perspective.

However the one downside of this is that you cannot revoke client sessions from the central state store - however as you have federated authx to the IDP, session revocation can be managed at that layer.

Additionally, some IDP tokens exceed the length of the cookie and will not be stored.

For larger deployments which require central state management, use the `redis` state store and configure `SESSION_STORE_REDIS` to point at your redis instance.

For local testing, the `filesystem` state store will store all sessions on disk. This provides central state management but cannot horizontally scale.

`SESSION_KEY` must be 32 bytes or larger. This key is used for both the API session management, as well as to encrypt the SSO cookie as it is passed between SSO domains.

#### config.json

Fill in `devops/k8s/secret.yaml` with your OAuth application information.

`config.json` contains all of the OAuth2 IdP configurations for the application.

Multiple OAuth providers can be configured in the `config.json` list.

```
[
  {
    "ID": "my_custom_id",
    "OAuth2": {
      "ClientID": "",
      "ClientSecret": "",
      "Endpoint": {
          "AuthURL": "https://login.microsoftonline.com/common/oauth2/authorize",
          "TokenURL": "https://login.microsoftonline.com/common/oauth2/token"
      },
      "RedirectURL": "http://localhost/callback"
    },
    "LogoutURL": "https://login.microsoftonline.com/common/oauth2/logout",
    "CookieName": "oauth2_sso",
    "DefaultRedirectURI": "https://example.com",
    "SSODomain": ".example.com"
  }
]
```

The first object in the list is the default if no ClientID is specified on initial login.

However, you can configure your envoy filter to redirect to `https://login.example.com/oauth2/{ID}` and this will authenticate the user with the application configured with this ID.

This enables you to configure different IDP applications and scopes and grant granular access to users on a service-by-service basis while still maintaining a seamless SSO across the mesh.

If you are using multiple additive SSO integrations, it is recommended that you rename the cookie and header of your additional filters so that they do not conflict with the default SSO integration.

Edit `devops/k8s/istio-envoy-filter.yaml` to include your redirect URL for unauthenticated users, and your `workloadSelector` if desired. The default will attach the filter to any Pod labeled `oauth2sso: enabled`.

#### Multiple SSO Domain Support

To enable, create a record on each target domain which points back to this API, and then configure the `VirtualService` for this API to listen on all supported SSO domains.

### Deploy

```
kubectl apply \
    -f devops/k8s/istio-envoy-filter.yaml \
    -f devops/k8s/secret.yaml \
    -f devops/k8s/deploy.yaml \
    -f devops/k8s/service.yaml
```

Create a `VirtualService` according to your mesh configuration to route to your `oauth2-sso` service. This `VirtualService` must be accessible for unauthenticated users, as this is what will handle the user's OIDC flow.

Ensure you have configured your callback URLs in both the API layer and in your OAuth2 provider.

### Mesh Configuration

Once deployed, users trying to access a workload with the `oauth2sso: enabled` label will be redirected to the IDP. After a successful log in, a `oauth2_sso` cookie will be set on the domain defined for the mesh, and the user will be redirected back to the original page.

The `EnvoyFilter` will then take the `oauth2_sso` cookie from the request and modify the request headers to add this as a `x-oauth2-sso` header. 

Your `RequestAuthentication` will need to be configured to use this header. Example:

```
apiVersion: "security.istio.io/v1beta1"
kind: "RequestAuthentication"
metadata:
  name: grafana
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: grafana
  jwtRules:
  - issuer: "https://sts.windows.net/APP_ID/"
    jwksUri: "https://sts.windows.net/APP_ID/discovery/v2.0/keys"
    fromHeaders:
    - name: x-oauth2-sso
```

#### Auth Header: x-oauth2-sso

The reasoning for using a custom header for the SSO JWT over the default `Authorization: Bearer ...` is to ensure that the SSO token injection does not conflict with existing application authx implementations.

If an application behind this auth layer implements its own authentication scheme, it can continue to do so without conflicting with the additional SSO layer above it.

Additionally, if the application implements its own integration with the same IDP as the top-level SSO this integration provides, the additional authx of the application-specific scopes is a seamless SSO into that role.

## Disclaimers and Notes

### Active Development Note

This solution was tested against Istio 1.6 and assumes an intermediate level of understanding with Istio, Envoy, and the OIDC flow. 

As with anything working against bleeding edge technology, RTFM & YMMV.

The API is being improved and optimized. All effort will be taken to ensure breaking changes are properly versioned according to SemVer but please be sure to version your imports out of an abundance of caution.

#### Upcoming Features

This is the first version of this implementation and there are already a few features that are clearly needed. Expect the following list to ebb and flow as more features are defined and subsequently implemented.

If you have a feature request, please raise it as a GitHub issue for proper tracking.

- More intelligent 403 handling
    - Currently if the application returns a `403` to envoy, it will immediately `302` to the IDP.
    - This does not account for valid app-internal `403` errors.
    - Additional logic should be added around the redirect functionality
- Management API
    - Currently, all OAuth2 application configuration is managed with the `config.json` file which is assumed to be injected as a Kuberenetes Secret.
    - However as the list of OAuth2 integrations grows, it will become cumbersome managing a JSON configuration file, patching secrets, restarting pods, etc.
    - While I am generally averse to adding infrastructure / complexity to what is supposed to be a lean interchange process, I can see the long term benefit in some centralized configuration management.
    - Chicken and Egg - how to auth the API which itself manages federated auth configuration
    - For now, using k8s operator RBAC and constructs to manage configuration

### Credits

While I would like to take credit for this design, it would be doing a disservice to the Istio community which I have leaned heavily on to develop this solution.

Thanks to Google and their team who have been a great resource.

Additional thanks to the users in [this GitHub issue](https://github.com/istio/istio/issues/8619) for the EnvoyProxy Lua examples and discussion.

And of course, thanks to my team who have been integral to the Istio design, build, implementation, and testing.

### Contributing

Feature requests, suggestions, and pull requests are welcome. 

However if there is a feature you need immediately, it is recommended that you fork this repo, implement your changes there, and PR back here once your changes are tested and stable in your mesh.


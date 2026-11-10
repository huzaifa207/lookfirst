//! Git over https: GET the advertisement, POST each command.

use super::*;

pub(super) fn describe(e: ureq::Error, token: bool) -> String {
    match e {
        ureq::Error::StatusCode(401 | 403 | 404) if token => {
            "the access token wasn't accepted, or it can't see this repository".into()
        }
        ureq::Error::StatusCode(401 | 403 | 404) => "it wasn't found, or it's private (add an access token to check \
                                                        a private repository, or use its ssh address)"
            .into(),
        ureq::Error::TooManyRedirects => "it has moved to another address; use the new one".into(),
        ureq::Error::StatusCode(code) => format!("the server answered {code}"),
        other => format!("it couldn't be reached ({other})"),
    }
}

pub(super) struct Http {
    pub(super) agent: ureq::Agent,
    pub(super) base: String,
    /// The whole "Authorization" header value, when there is a token.
    pub(super) auth: Option<String>,
}

impl Http {
    pub(super) fn read(
        &self,
        response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<Vec<u8>, String> {
        let token = self.auth.is_some();
        let mut response = response.map_err(|e| describe(e, token))?;
        if response.status().is_redirection() {
            // Never follow a redirect with a token: it could lead to another site.
            return Err("it has moved to another address; use the new one".into());
        }
        response.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(|e| describe(e, token))
    }
}

impl Transport for Http {
    fn advertise(&mut self) -> Result<Vec<u8>, String> {
        let mut request = self
            .agent
            .get(&format!("{}/info/refs?service=git-upload-pack", self.base))
            .header("Git-Protocol", "version=2");
        if let Some(auth) = &self.auth {
            request = request.header("Authorization", auth);
        }
        self.read(request.call())
    }

    fn command(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let mut request = self
            .agent
            .post(&format!("{}/git-upload-pack", self.base))
            .header("Git-Protocol", "version=2")
            .header("Content-Type", "application/x-git-upload-pack-request")
            .header("Accept", "application/x-git-upload-pack-result");
        if let Some(auth) = &self.auth {
            request = request.header("Authorization", auth);
        }
        self.read(request.send(body))
    }
}

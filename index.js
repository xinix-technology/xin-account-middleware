import { define } from '@xinix/xin';
import { Middleware } from '@xinix/xin/components';
import qs from 'qs';
import jwt from 'jsonwebtoken';

const { btoa, atob, location, localStorage } = window;

class XinAccountMiddleware extends Middleware {
  get props () {
    return Object.assign({}, super.props, {
      location: {
        type: Object,
        value: () => location,
      },

      storage: {
        type: Object,
        value: () => localStorage,
      },

      baseUrl: {
        type: String,
      },

      clientId: {
        type: String,
      },
    });
  }

  callback () {
    return async (ctx, next) => {
      let hash = this.location.hash;
      if (hash.startsWith('#access_token=')) {
        try {
          let authData = qs.parse(hash.substr(1));
          this.save(authData.access_token);
          try {
            let state = JSON.parse(atob(authData.state));
            this.location.replace(`#!${state.uri}`);
          } catch (err) {
            this.location.replace(`#!/`);
          }
          await sleep(300);
          return;
        } catch (err) {
          throw err;
        }
      }

      this.init();
      await this.refresh();

      if (!this.token) {
        this.signin();
        await sleep(300);
        return;
      }

      await next();
    };
  }

  init () {
    if (this.token) {
      return;
    }

    let token = this.storage.APP_TOKEN;
    if (token && !this.decode(token)) {
      this.invalidate();
      token = undefined;
    }

    this.save(token);
  }

  signin () {
    let state = btoa(JSON.stringify({
      uri: this.location.hash.split('#!').pop(),
    }));
    this.location.href = `${this.baseUrl}/oauth/auth?client_id=${this.clientId}&response_type=token&response_mode=fragment&state=${state}`;
  }

  signout () {
    this.invalidate();
    this.location.href = `${this.baseUrl}/oauth/signout?client_id=${this.clientId}`;
  }

  async refresh () {
    try {
      let resp = await window.fetch(`${this.baseUrl}/oauth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          access_token: this.token,
        }),
      });

      if (resp.status === 401) {
        return this.invalidate();
      }

      if (resp.status === 200) {
        let body = await resp.json();
        if (!body.access_token) {
          return this.invalidate();
        }

        this.save(body.access_token);
      }
    } catch (err) {
      // noop
    }
  }

  save (token = '') {
    if (token) {
      this.storage.APP_TOKEN = token;
    } else {
      delete this.storage.APP_TOKEN;
    }
    this.token = token;
    this.fire('token-change', token);
  }

  invalidate () {
    this.save();
  }

  decode (token) {
    return jwt.decode(token);
  }
}

define('xin-account-middleware', XinAccountMiddleware);

function sleep (t = 0) {
  return new Promise(resolve => setTimeout(resolve, t));
}

"""
Registration Service
Location: src/services/registration.py

Flow:
  1. register(email, password, username)
       - validate input
       - reject disposable email domains
       - hash password
       - save user with is_verified=False, is_active=False
       - generate a 12-hour verification token
       - return RegisterPending (caller sends the email)
       - NO keypair yet

  2. verify_email(token)
       - validate token exists and not expired
       - mark is_verified=True, is_active=True
       - NOW generate P-256 keypair
       - return RegisterResult with private_key_pem (once, never stored)
"""

import os
import secrets
import hmac as _hmac
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta

import jwt as _jwt

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from src.services.store import get_store
from src.services.config import cfg
from src.crypto.key_manager import KeyManager

logger = logging.getLogger(__name__)

_key_manager = KeyManager()
_TOKEN_TTL_HOURS = 12


# ── Disposable email blocklist ────────────────────────────────────────────────
# Hardcoded for now. Replace with a fetched community list later.

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net",
    "guerrillamail.org", "guerrillamail.de", "guerrillamail.info",
    "guerrillamail.biz", "tempmail.com", "tempmail.net", "tempmail.org",
    "temp-mail.org", "throwam.com", "throwam.net", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "spam4.me", "yopmail.com",
    "yopmail.fr", "cool.fr.nf", "jetable.fr.nf", "nospam.ze.tc",
    "nomail.xl.cx", "mega.zik.dj", "speed.1s.fr", "courriel.fr.nf",
    "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf",
    "trashmail.com", "trashmail.me", "trashmail.net", "trashmail.org",
    "trashmail.at", "trashmail.io", "trashmail.xyz", "dispostable.com",
    "mailnull.com", "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
    "maildrop.cc", "throwam.com", "fakeinbox.com", "mailnesia.com",
    "mailnull.com", "spamfree24.org", "spamfree24.de", "spamfree24.eu",
    "spamfree24.info", "spamfree24.net", "spamfree24.org", "spamfree.eu",
    "spam.la", "spoofmail.de", "discard.email", "discardmail.com",
    "discardmail.de", "spamspot.com", "spamspot.net", "spamspot.org",
    "0-mail.com", "0815.ru", "0815.su", "0clickemail.com", "0wnd.net",
    "0wnd.org", "10minutemail.com", "10minutemail.net", "10minutemail.org",
    "20minutemail.com", "20minutemail.it", "21cn.com", "2fdgdfgdfgdf.tk",
    "33mail.com", "3d-painting.com", "4warding.com", "4warding.net",
    "4warding.org", "60minutemail.com", "675hosting.com", "6hjgjhgkilkj.tk",
    "6paq.com", "6url.com", "75hosting.com", "7tags.com", "9ox.net",
    "agedmail.com", "amilegit.com", "amiri.net", "anonymail.dk",
    "antichef.com", "antichef.net", "antireg.com", "antireg.ru",
    "antispam.de", "armyspy.com", "baxomale.ht.cx", "beefmilk.com",
    "bigstring.com", "binkmail.com", "bio-muesli.net", "bobmail.info",
    "bodhi.lawlita.com", "bofthew.com", "bootybay.de", "boun.cr",
    "bouncr.com", "breakthru.com", "brefmail.com", "bsnow.net",
    "bugmenot.com", "bumpymail.com", "casualdx.com", "cek.pm",
    "centermail.com", "centermail.net", "chammy.info", "childsafemail.com",
    "chogmail.com", "choicemail1.com", "clixser.com", "cmail.net",
    "cmail.org", "coldemail.info", "cool.fr.nf", "correo.blogos.net",
    "cosmorph.com", "courriel.fr.nf", "crapmail.org", "crazymailing.com",
    "cubiclink.com", "curryworld.de", "cust.in", "dacoolest.com",
    "daemsteam.com", "dandikmail.com", "dayrep.com", "deadaddress.com",
    "deadletter.ga", "deagot.com", "deal-maker.com", "deekayen.us",
    "delikkt.de", "despam.it", "despammed.com", "devnullmail.com",
    "dingbone.com", "disposableaddress.com", "disposableemailaddresses.com",
    "disposableinbox.com", "disposeamail.com", "disposemail.com",
    "divermail.com", "dm.w3internet.co.uk", "dodgeit.com", "dodgmail.de",
    "donemail.ru", "dontreg.com", "dontsendmespam.de", "drdrb.com",
    "drdrb.net", "dropmail.me", "dumpandfuck.com", "dumpmail.de",
    "dumpyemail.com", "e4ward.com", "easytrashmail.com", "emailage.cf",
    "emailage.ga", "emailage.gq", "emailage.ml", "emailage.tk",
    "emaildienst.de", "emailigo.com", "emailinfive.com", "emailisvalid.com",
    "emailmiser.com", "emailsensei.com", "emailtemporario.com.br",
    "emailthe.net", "emailtmp.com", "emailwarden.com", "emailx.at.hm",
    "emailxfer.com", "emeil.in", "emeil.ir", "emz.net", "enterto.com",
    "ephemail.net", "etranquil.com", "etranquil.net", "etranquil.org",
    "explodemail.com", "express.net.ua", "extremail.ru", "eyepaste.com",
    "ezfill.com", "fake-email.pp.ua", "fakemailgenerator.com",
    "fakemail.fr", "fakemailz.com", "fammix.com", "fansworldwide.de",
    "fastacura.com", "fastchevy.com", "fastchrysler.com", "fastkawasaki.com",
    "fastmazda.com", "fastmitsubishi.com", "fastnissan.com", "fastsubaru.com",
    "fastsuzuki.com", "fasttoyota.com", "fastyamaha.com", "filzmail.com",
    "fleckens.hu", "flurred.com", "frapmail.com", "freundin.ru",
    "front14.org", "fuckingduh.com", "fudgerub.com", "fux0ringduh.com",
    "garliclife.com", "gehensiemirnichtaufdengeist.de", "gelitik.in",
    "get-mail.cf", "get-mail.ga", "get-mail.ml", "get-mail.tk",
    "getonemail.com", "getonemail.net", "ghosttexter.de", "girlsundertheinfluence.com",
    "gishpuppy.com", "gmailnew.com", "goemailgo.com", "gorillaswithdirtyarmpits.com",
    "gotmail.com", "gotmail.net", "gotmail.org", "gowikibooks.com",
    "gowikicampus.com", "gowikicars.com", "gowikifilms.com", "gowikigames.com",
    "gowikimusic.com", "gowikinetwork.com", "gowikitravel.com", "gowikitv.com",
    "grandmamail.com", "grandmasmail.com", "great-host.in", "greensloth.com",
    "grr.la", "gsrv.co.uk", "guerillamail.biz", "guerillamail.com",
    "guerillamail.de", "guerillamail.info", "guerillamail.net", "guerillamail.org",
    "guerillamailblock.com", "gustr.com", "h.mintemail.com", "hab.al",
    "haltospam.com", "hatespam.org", "herp.in", "hidemail.de",
    "hidzz.com", "hmamail.com", "hopemail.biz", "ieatspam.eu",
    "ieatspam.info", "ihateyoualot.info", "iheartspam.org", "imails.info",
    "inbax.tk", "inbox.si", "inboxalias.com", "inboxclean.com",
    "inboxclean.org", "incognitomail.com", "incognitomail.net",
    "incognitomail.org", "inoutmail.de", "inoutmail.eu", "inoutmail.info",
    "inoutmail.net", "insorg.org", "instant-mail.de", "instantemailaddress.com",
    "instantmail.fr", "ip6.li", "irish2me.com", "iwi.net",
    "jetable.com", "jetable.fr.nf", "jetable.net", "jetable.org",
    "jnxjn.com", "jourrapide.com", "jsrsolutions.com", "junk.to",
    "justamail.net", "kasmail.com", "kaspop.com", "keepmymail.com",
    "killmail.com", "killmail.net", "kimsdisk.com", "kingsq.ga",
    "klassmaster.com", "klassmaster.net", "klzlk.com", "koszmail.pl",
    "kurzepost.de", "lawlita.com", "lazyinbox.com", "letthemeatspam.com",
    "lhsdv.com", "lifebyfood.com", "link2mail.net", "litedrop.com",
    "lol.ovpn.to", "lollipop.uk", "lookugly.com", "lortemail.dk",
    "lr78.com", "lroid.com", "lukop.dk", "m21.cc",
    "mail-filter.com", "mail-temporaire.fr", "mail.by", "mail.mezimages.net",
    "mail.zp.ua", "mail1a.de", "mail21.cc", "mail2rss.org",
    "mail333.com", "mailbidon.com", "mailbiz.biz", "mailblocks.com",
    "mailbucket.org", "mailcat.biz", "mailcatch.com", "mailde.de",
    "mailde.info", "maildrop.cc", "maileater.com", "mailed.ro",
    "mailexpire.com", "mailf5.com", "mailfa.tk", "mailforspam.com",
    "mailfreeonline.com", "mailguard.me", "mailhazard.com", "mailhazard.us",
    "mailimate.com", "mailin8r.com", "mailinater.com", "mailinator.net",
    "mailinator.org", "mailinator.us", "mailinator2.com", "mailincubator.com",
    "mailismagic.com", "mailme.ir", "mailme.lv", "mailme24.com",
    "mailmetrash.com", "mailmoat.com", "mailms.com", "mailnew.com",
    "mailnull.com", "mailpick.biz", "mailproxsy.com", "mailquack.com",
    "mailrock.biz", "mailsac.com", "mailscrap.com", "mailshell.com",
    "mailsiphon.com", "mailslite.com", "mailsoul.com", "mailsucker.net",
    "mailtome.de", "mailtothis.com", "mailtrash.net", "mailtrix.net",
    "mailzilla.com", "mailzilla.org", "makemetheking.com", "malahov.de",
    "manifestgram.com", "manybrain.com", "mbx.cc", "mega.zik.dj",
    "meinspamschutz.de", "meltmail.com", "messagebeamer.de", "mezimages.net",
    "mierdamail.com", "migumail.com", "mindless.com", "mintemail.com",
    "misterpinball.de", "mmdrive.com", "mmmmail.com", "moaktmail.com",
    "mohmal.com", "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf",
    "monumentmail.com", "moot.es", "mozmail.com", "msa.minsmail.com",
    "mt2009.com", "mt2014.com", "mt2015.com", "mt2016.com",
    "muhosransk.net", "mutant.me", "myfastmail.com", "mymacmail.com",
    "mypartyclip.de", "myphantomemail.com", "myspaceinc.com", "myspaceinc.net",
    "myspaceinc.org", "myspacepimpers.com", "myspamless.com", "mytrashmail.com",
    "netmails.com", "netmails.net", "netzidiot.de", "nevermail.de",
    "newbpotato.tk", "nice-4u.com", "nincsmail.hu", "nk0.com",
    "nnh.com", "nobulk.com", "noclickemail.com", "nogmailspam.info",
    "nomail.pw", "nomail.xl.cx", "nomail2me.com", "nomorespamemails.com",
    "nonspam.eu", "nonspammer.de", "noref.in", "nospam.ze.tc",
    "nospam4.us", "nospamfor.us", "nospammail.net", "nospamthanks.info",
    "notmailinator.com", "notsharingmy.info", "nowmymail.com", "nwldx.com",
    "objectmail.com", "obobbo.com", "odnorazovoe.ru", "oneoffmail.com",
    "onewaymail.com", "onlatedotcom.info", "online.ms", "oopi.org",
    "opayq.com", "ordinaryamerican.net", "otherinbox.com", "ovpn.to",
    "owlpic.com", "pancakemail.com", "paplease.com", "pcusers.otherinbox.com",
    "pepbot.com", "peterdethier.com", "phantomemail.de", "phentermine-mortgages.com",
    "pimpedupmyspace.com", "pjjkp.com", "plexolan.de", "poczta.onet.pl",
    "politikerclub.de", "poofy.org", "pookmail.com", "privacy.net",
    "privatdemail.net", "proxymail.eu", "prtnx.com", "prtz.eu",
    "pubmail.io", "putthisinyourspamdatabase.com", "qq.com",
    "quickinbox.com", "quickmail.nl",
    "rcpt.at", "recode.me", "recursor.net", "recyclemail.dk",
    "regbypass.com", "regbypass.comsafe-mail.net", "rejectmail.com",
    "rklips.com", "rmqkr.net", "royal.net", "rppkn.com",
    "rtrtr.com", "s0ny.net", "safe-mail.net", "safersignup.de",
    "safetymail.info", "safetypost.de", "sandelf.de", "saynotospams.com",
    "selfdestructingmail.com", "sendspamhere.com", "senseless-entertainment.com",
    "services391.com", "sharklasers.com", "shieldedmail.com", "shiftmail.com",
    "shitmail.me", "shitmail.org", "shitware.nl", "shmeriously.com",
    "shortmail.net", "sibmail.com", "skeefmail.com", "slapsfromlastnight.com",
    "slaskpost.se", "slave-auctions.net", "slopsbox.com", "slowslow.de",
    "slushmail.com", "smashmail.de", "smellfear.com", "smellrear.com",
    "snakemail.com", "sneakemail.com", "sneakmail.de", "snkmail.com",
    "sofimail.com", "sofort-mail.de", "softpls.asia", "sogetthis.com",
    "soodonims.com", "spam.la", "spam.su", "spam4.me",
    "spamavert.com", "spambob.com", "spambob.net", "spambob.org",
    "spambog.com", "spambog.de", "spambog.ru", "spambox.info",
    "spambox.irishspringrealty.com", "spambox.us", "spamcannon.com",
    "spamcannon.net", "spamcero.com", "spamcon.org", "spamcorptastic.com",
    "spamcowboy.com", "spamcowboy.net", "spamcowboy.org", "spamday.com",
    "spamex.com", "spamfree.eu", "spamfree24.de", "spamfree24.eu",
    "spamfree24.info", "spamfree24.net", "spamfree24.org", "spamgoes.in",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org", "spamherelots.com",
    "spamhereplease.com", "spamhole.com", "spamify.com", "spaminator.de",
    "spamkill.info", "spaml.com", "spaml.de", "spammotel.com",
    "spamoff.de", "spamouflage.com", "spamout.com", "spampedia.net",
    "spamspot.com", "spamstack.net", "spamthis.co.uk", "spamthisplease.com",
    "spamtrap.ro", "spamtrash.net", "spamwc.com", "spamwc.de",
    "spamwc.net", "spamwc.org", "specimail.de", "speed.1s.fr",
    "spikio.com", "spoofmail.de", "squizzy.de", "squizzy.eu",
    "squizzy.net", "st-laza.ru", "stinkefinger.net", "stuffmail.de",
    "super-auswahl.de", "supergreatmail.com", "supermailer.jp", "superrito.com",
    "superstachel.de", "suremail.info", "svk.jp", "sweetxxx.de",
    "tafmail.com", "tagyourself.com", "talifun.com", "tapchicuoihoi.com",
    "tecxyz.com", "teewars.org", "teleworm.com", "teleworm.us",
    "temp-mail.ru", "tempalias.com", "tempe-mail.com", "tempemail.biz",
    "tempemail.co.za", "tempemail.com", "tempemail.net", "tempemail.org",
    "tempinbox.co.uk", "tempinbox.com", "tempmail.de", "tempmail.eu",
    "tempmail.it", "tempmail2.com", "tempmailer.com", "tempmailer.de",
    "tempr.email", "tempsky.com", "tempthe.net", "tempymail.com",
    "thanksnospam.info", "thc.st", "thelimestoneking.com", "thetempmail.com",
    "thex.ro", "thisisnotmyrealemail.com", "throam.com", "throwam.com",
    "throwmail.net", "throwthis.xyz", "tilien.com", "tittbit.in",
    "tmail.com", "tmailinator.com", "toiea.com", "toomail.biz",
    "topranklist.de", "tradermail.info", "trash-amil.com", "trash-mail.at",
    "trash-mail.cf", "trash-mail.com", "trash-mail.de", "trash-mail.ga",
    "trash-mail.gq", "trash-mail.io", "trash-mail.me", "trash-mail.ml",
    "trash-mail.net", "trash-mail.org", "trash-mail.tk", "trash2009.com",
    "trash2010.com", "trash2011.com", "trashdevil.com", "trashdevil.de",
    "trashemail.de", "trashimail.de", "trashow.com", "trashmail.app",
    "trashmail.at", "trashmail.com", "trashmail.io", "trashmail.me",
    "trashmail.net", "trashmail.org", "trashmail.xyz", "trashmailer.com",
    "trashymail.com", "trashymail.net", "trbvm.com", "trbvn.com",
    "trbvo.com", "trickmail.net", "trillianpro.com", "tryalert.com",
    "turual.com", "twinmail.de", "tyldd.com", "umail.net",
    "umail2.com", "unmail.ru", "upliftnow.com", "uplipht.com",
    "uroid.com", "us.af", "venompen.com", "veryrealemail.com",
    "vidchart.com", "viditag.com", "viewcastmedia.com", "viewcastmedia.net",
    "viewcastmedia.org", "viralplays.com", "vmail.me", "vomoto.com",
    "vubby.com", "walkmail.net", "walkmail.ru", "webemail.me",
    "webm4il.info", "wegwerfadresse.de", "wegwerfemail.com", "wegwerfemail.de",
    "wegwerfemail.net", "wegwerfemail.org", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "wegwerfnummer.de", "wetrainbayarea.com", "wetrainbayarea.org",
    "whyspam.me", "willhackforfood.biz", "willselfdestruct.com", "winemaven.info",
    "wronghead.com", "wuzupmail.net", "www.e4ward.com", "www.gishpuppy.com",
    "www.mailinator.com", "wwwnew.eu", "xagloo.co", "xagloo.com",
    "xemaps.com", "xents.com", "xmaily.com", "xoxy.net",
    "xww.ro", "xyzfree.net", "yapped.net", "yeah.net",
    "yepmail.net", "yert.ye.vc", "yogamaven.com", "yomail.info",
    "yopmail.com", "yopmail.fr", "yourdomain.com", "ypmail.webarnak.fr.eu.org",
    "yuurok.com", "z1p.biz", "za.com", "zehnminuten.de",
    "zehnminutenmail.de", "zippymail.info", "zoemail.com", "zoemail.net",
    "zoemail.org", "zomg.info",
}


# ── Exceptions ────────────────────────────────────────────────────────────────

class RegistrationError(Exception):
    pass

class UserAlreadyExistsError(RegistrationError):
    pass

class InvalidTokenError(RegistrationError):
    pass

class AuthenticationError(Exception):
    pass


# ── Result objects ────────────────────────────────────────────────────────────

@dataclass
class RegisterPending:
    """Returned by register(). Account exists but is not active yet."""
    user_id:            int
    email:              str
    username:           str
    verification_token: str   # send this in the email link
    token_expires_at:   str   # ISO UTC — show user when it expires

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RegisterResult:
    """Returned by verify_email(). Account is now active."""
    user_id:         int
    email:           str
    username:        str
    public_key_hex:  str   # uncompressed P-256, 130 hex chars
    public_key_hash: str   # SHA-256 of pub key bytes, 64 hex chars
    private_key_pem: str   # SAVE THIS — never stored, returned once only
    created_at:      str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LoginResult:
    """Returned by login(). JWT + public identity material."""
    user_id:               int
    email:                 str
    username:              str
    full_name:             str
    role:                  str
    public_key_hash:       str
    public_key_compressed: str
    access_token:          str   # signed JWT
    token_type:            str = "bearer"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Service ───────────────────────────────────────────────────────────────────

class RegistrationService:

    def __init__(self):
        self.store = get_store()

    def register(
        self,
        email: str,
        password: str,
        username: str,
        full_name: str = "",
        role: str = "PATIENT",
        public_key_hex: str = None,
        public_key_compressed: str = None,
        public_key_hash: str = None,
    ) -> RegisterPending:
        """
        Step 1. Validate → check disposable domain → hash password →
                save inactive user → return verification token.
        No keypair generated yet.
        """
        email    = email.strip().lower()
        username = username.strip()
        full_name = (full_name or "").strip()

        # ── input validation ──────────────────────────────────────────────────
        if not email or "@" not in email:
            raise RegistrationError("Invalid email address")
        if not password or len(password) < 8:
            raise RegistrationError("Password must be at least 8 characters")
        if not username or len(username) < 3:
            raise RegistrationError("Username must be at least 3 characters")

        # ── disposable email check ────────────────────────────────────────────
        domain = email.split("@")[1]
        if domain in _DISPOSABLE_DOMAINS:
            raise RegistrationError(
                "Disposable email addresses are not allowed. "
                "Please use a real email address."
            )

        # ── hash password ─────────────────────────────────────────────────────
        pw_hash = _hash_password(password)

        # ── verification token (URL-safe, 32 random bytes → 64 hex chars) ─────
        token      = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=_TOKEN_TTL_HOURS)

        # ── persist (inactive until email verified) ───────────────────────────
        try:
            user = self.store.create_user(
                email=email,
                username=username,
                full_name=full_name,
                role=role,
                password_hash=pw_hash,
                verification_token=token,
                token_expires_at=expires_at.isoformat(),
            )
        except ValueError as e:
            raise UserAlreadyExistsError(str(e))
        except Exception as e:
            raise RegistrationError(f"Storage error: {e}")

        self.store.append_audit(
            user_id=user.id,
            action="REGISTRATION_STARTED",
            description=f"Pending verification: {email}",
        )

        logger.info("registration pending user_id=%s email=%s", user.id, email)

        return RegisterPending(
            user_id=user.id,
            email=email,
            username=username,
            verification_token=token,
            token_expires_at=expires_at.isoformat(),
        )

    def verify_email(self, token: str) -> RegisterResult:
        """
        Step 2. Validate token → activate account → generate keypair →
                return RegisterResult with private_key_pem (once only).
        """
        user = self.store.get_by_verification_token(token)

        if not user:
            raise InvalidTokenError("Invalid verification token")

        # check expiry
        expires_at = datetime.fromisoformat(user.token_expires_at)
        if datetime.now(timezone.utc) > expires_at:
            raise InvalidTokenError(
                "Verification token has expired. Please register again."
            )

        if user.is_verified:
            raise InvalidTokenError("Email already verified")

        # ── generate keypair now that we know the email is real ───────────────
        keypair = _key_manager.generate_keypair()

        # ── activate the account ──────────────────────────────────────────────
        self.store.activate_user(
            user_id=user.id,
            public_key_hex=keypair.public_key_hex,
            public_key_compressed=keypair.public_key_compressed,
            public_key_hash=keypair.public_key_hash,
        )

        self.store.append_audit(
            user_id=user.id,
            action="EMAIL_VERIFIED",
            description=f"Account activated: {user.email}",
        )

        logger.info("email verified user_id=%s", user.id)

        return RegisterResult(
            user_id=user.id,
            email=user.email,
            username=user.username,
            public_key_hex=keypair.public_key_hex,
            public_key_hash=keypair.public_key_hash,
            private_key_pem=keypair.private_key_pem,
            created_at=user.created_at,
        )

    def login(self, email: str, password: str) -> LoginResult:
        """
        Authenticate with email + password.
        Returns a signed JWT and the user's public identity material.
        Raises AuthenticationError on any failure (deliberately vague to
        prevent user enumeration).
        """
        email = email.strip().lower()
        _GENERIC = "Invalid email or password"

        user = self.store.get_by_email(email)
        if not user:
            raise AuthenticationError(_GENERIC)

        if not user.is_active:
            raise AuthenticationError("Account is not active. Check your verification email.")

        if not _verify_password(password, user.password_hash):
            self.store.append_audit(
                user_id=user.id,
                action="LOGIN_FAILED",
                description=f"Bad password attempt: {email}",
            )
            raise AuthenticationError(_GENERIC)

        # ── stamp last_login ──────────────────────────────────────────────────
        self.store.set_last_login(user_id=user.id)
        self.store.append_audit(
            user_id=user.id,
            action="LOGIN_SUCCESS",
            description=f"Authenticated: {email}",
        )

        logger.info("login success user_id=%s", user.id)

        token = _issue_jwt(user.id, email)

        return LoginResult(
            user_id=user.id,
            email=user.email,
            username=user.username,
            full_name=user.full_name or "",
            role=user.role or "PATIENT",
            public_key_hash=user.public_key_hash,
            public_key_compressed=user.public_key_compressed,
            access_token=token,
        )

    @staticmethod
    def verify_token(token: str) -> dict:
        """
        Decode and validate a JWT issued by this service.
        Returns the payload dict (sub, email, exp, iat).
        Raises AuthenticationError if the token is invalid or expired.
        """
        try:
            payload = _jwt.decode(
                token,
                cfg.jwt_secret,
                algorithms=[cfg.jwt_algorithm],
            )
            return payload
        except _jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except _jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")


# ── Password helpers ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256, 100k iterations, 32-byte random salt.
    Format: sha256$<iterations>$<salt_hex>$<hash_hex>"""
    iterations = 100_000
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    h = kdf.derive(password.encode("utf-8"))
    return f"sha256${iterations}${salt.hex()}${h.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash string.
    Constant-time comparison prevents timing attacks."""
    try:
        scheme, iterations_str, salt_hex, hash_hex = stored_hash.split("$")
        if scheme != "sha256":
            return False
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        candidate = kdf.derive(password.encode("utf-8"))
        return _hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _issue_jwt(user_id: int, email: str) -> str:
    """Sign and return a JWT with standard claims."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub":   str(user_id),
        "email": email,
        "iat":   now,
        "exp":   now + timedelta(hours=cfg.jwt_expiration_hours),
    }
    return _jwt.encode(payload, cfg.jwt_secret, algorithm=cfg.jwt_algorithm)

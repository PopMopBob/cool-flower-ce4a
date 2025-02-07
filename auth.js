export default function handler(req, res) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Secure Area"');
    return res.status(401).send("Unauthorized");
  }

  const credentials = Buffer.from(authHeader.split(" ")[1], "base64")
    .toString()
    .split(":");
  const [user, pass] = credentials;

  if (user !== "admin" || pass !== "mySecretPassword") {
    res.setHeader("WWW-Authenticate", 'Basic realm="Secure Area"');
    return res.status(401).send("Unauthorized");
  }

  return res.status(200).send("Authorized");
}

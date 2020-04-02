package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;


import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;

public interface SignatureValidationStrategy {

  /**
   * @param factory the PGPObjectFactory
   * @param onePassSignatures all signatures for which public keys have been found, indexed by
   *     pubKeyId.
   *
   * @throws SignatureException No satisfiable signature has been found (no signature for
   *     expected
   *     keys / broken signature)
   * @throws IOException IO is dangerous
   * @throws PGPException general error processing PGP
   */
  void validateSignatures(PGPObjectFactory factory,
      Map<Long, PGPOnePassSignature> onePassSignatures)
      throws SignatureException, PGPException, IOException;


  /**
   * @return Iff a signature is required for a document. false: All, even broken(!) signatures are
   *     ignored.
   * @param onePassSignatures the one-pass signatures that were present in the message being decrypted
   */
  boolean isRequireSignatureCheck(PGPOnePassSignatureList onePassSignatures);
}

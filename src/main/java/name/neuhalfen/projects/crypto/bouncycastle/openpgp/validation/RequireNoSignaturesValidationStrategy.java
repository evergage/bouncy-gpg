package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;

import java.util.Map;

final class RequireNoSignaturesValidationStrategy implements SignatureValidationStrategy {

  // Note, this method will never actually get called, because if the encrypted message contains any signatures,
  // DecryptionStreamFactory will have already thrown an exception due to state.hasVerifiableSignatures() being false.
  @Override
  public void validateSignatures(PGPObjectFactory factory,
      Map<Long, PGPOnePassSignature> onePassSignatures) throws PGPException {
    throw new PGPException("Signatures found.");
  }


  @Override
  public boolean isRequireSignatureCheck(PGPOnePassSignatureList onePassSignatures) {
    return onePassSignatures.size() >= 1;
  }
}

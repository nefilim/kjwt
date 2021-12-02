package io.github.nefilim.kjwt.googlekms

import io.grpc.Metadata
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe

class GoogleKMSSpec: WordSpec() {
    init {
        "kmsParentLocationHeader" should {
            "parse a valid location correctly" {
                val metadata = Metadata()
                kmsParentLocationHeader("projects/figure-dev-shadow/locations/us-east1/keyRings/service-aikyam", metadata).also {
                    metadata.put(GOOGLE_REQUEST_HEADER, "parent=projects/figure-dev-shadow/locations/us-east1")
                    it shouldBe metadata
                }
            }
            "must start with a letter" {
                val metadata = Metadata()
                kmsParentLocationHeader("projects/1figure-dev-shadow/locations/us-east1/keyRings/service-aikyam", metadata).also {
                    metadata.put(GOOGLE_REQUEST_HEADER, "parent=projects/figure-dev-shadow/locations/us-east1")
                    it shouldBe metadata
                }
            }
        }
    }
}
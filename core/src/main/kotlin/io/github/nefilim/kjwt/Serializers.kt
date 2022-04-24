package io.github.nefilim.kjwt

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

class UnsupportedAlgorithmException(val algorithm: String): Exception("unsupported JWS algorithm: [$algorithm]")

private val AllJWSAlgorithmToHeaderIDs = AllAlgorithms.associateBy { it.headerID }

@OptIn(ExperimentalSerializationApi::class)
@Serializer(forClass = JWSAlgorithm::class)
object JWSAlgorithmSerializer: KSerializer<JWSAlgorithm> {

    override fun deserialize(decoder: Decoder): JWSAlgorithm {
        val alg = decoder.decodeString().trim().uppercase()
        return AllJWSAlgorithmToHeaderIDs[alg] ?: throw UnsupportedAlgorithmException(alg)
    }

    override fun serialize(encoder: Encoder, value: JWSAlgorithm) {
        encoder.encodeString(value.headerID)
    }

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JWSAlgorithm", PrimitiveKind.STRING)
}
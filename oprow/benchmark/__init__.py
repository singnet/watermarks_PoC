"""OProW Step 14 transform/adversarial benchmark harness."""

from .adversarial import (
    AdversarialVerificationCase,
    AlphaLSBStripTransform,
    RandomRectangleOcclusionTransform,
    TileAlphaErasureTransform,
    adversarial_image_transform_suite,
    copy_alpha_lsb_carrier,
)
from .essence import EssenceTrialResult, benchmark_essence_profile, benchmark_essence_separation, run_essence_trial
from .hdc import HDCTrialResult, benchmark_hdc_separation, benchmark_hdc_stability, run_hdc_trial
from .metrics import (
    ConfusionCounts,
    byte_difference_fraction,
    decode_rgb_array,
    finite_psnr_rgb,
    hamming_fraction_bits,
    mse_rgb,
    psnr_rgb,
    summarize_boolean_outcomes,
)
from .pipeline import BenchmarkHarness
from .reports import BenchmarkCase, BenchmarkReport, MetricSample, to_jsonable, utc_now_iso
from .samples import checker_sample, default_synthetic_image_corpus, gradient_sample, solid_with_stripe_sample
from .transforms import (
    ArtifactTransform,
    BrightnessContrastTransform,
    CenterCropTransform,
    GaussianBlurTransform,
    GaussianNoiseTransform,
    IdentityTransform,
    JPEGRecompressTransform,
    PNGRoundTripTransform,
    ResizeTransform,
    ScreenshotSimulationTransform,
    SocialPipelineTransform,
    TransformApplication,
    TransformSuite,
    hostile_image_transform_suite,
    quick_image_transform_suite,
    safe_apply_transform,
)
from .watermark import (
    PayloadFactory,
    WatermarkTrialResult,
    benchmark_watermark_profile,
    constant_payload_factory,
    run_watermark_trial,
)

__all__ = [name for name in globals() if not name.startswith("_")]
